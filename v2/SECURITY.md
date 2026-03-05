# Security Guide

Comprehensive security considerations and best practices for using auth v2.

## Table of Contents

1. [Password Security](#password-security)
2. [Token Security](#token-security)
3. [Database Security](#database-security)
4. [API Security](#api-security)
5. [Email Security](#email-security)
6. [Configuration Security](#configuration-security)
7. [Common Vulnerabilities](#common-vulnerabilities)
8. [Security Checklist](#security-checklist)

---

## Password Security

### Hashing Algorithm

**Used: Bcrypt**
- Adaptive algorithm with configurable work factor
- Automatically hashes and salts passwords
- Resistant to GPU/ASIC attacks
- Updates algorithm strength over time

**Configuration:**
```go
cfg := auth.DefaultConfig(jwtSecret, adminEmail)
cfg.BcryptCost = 10 // Default: bcrypt.DefaultCost

// Higher cost = more secure but slower
// Cost 10 ≈ 100ms per hash
// Cost 12 ≈ 250ms per hash
// Cost 14 ≈ 1 second per hash

store := postgres.New(pool, cfg)
```

**Not Used (Intentionally):**
- ❌ MD5 - Cryptographically broken
- ❌ SHA1/SHA256 - Fast to crack with GPUs
- ❌ PBKDF2 - Older, less resistant to hardware attacks
- ❌ Custom algorithms - Expert peer review required

### Password Strength Validation

**Enforced Requirements:**
```
✓ Minimum length: 8 characters (configurable)
✓ Maximum length: 72 characters (bcrypt limit)
✓ Uppercase letter: A-Z
✓ Lowercase letter: a-z
✓ Digit: 0-9
✓ Special character: punctuation or symbol
```

**Examples:**
```go
// Valid passwords
"MyPassword123!"      // ✓
"Secure@Pass456"     // ✓
"P@ssw0rd!"          // ✓

// Invalid passwords
"weak"               // ✗ Too short, missing requirements
"PASSWORD123!"       // ✗ No lowercase
"password123!"       // ✗ No uppercase
"MyPassword123"      // ✗ No special character
"abc"                // ✗ Too short
```

### Password Reset Security

**Token Generation:**
- 32 bytes of CSPRNG randomness
- 256 bits entropy
- Base64url encoded (43 characters)
- Non-reversible format

```go
// Generated token looks like:
// es_MOHB3ersvedm7IAGjIP16wGbXcGMz6CveZLVEhB8=
```

**Storage:**
- Only SHA-256 hash stored in database
- Raw token never persisted
- Hash is one-way (cannot reverse)

```go
rawToken := "es_MOHB3ers..."
tokenHash := HashResetToken(rawToken)
// tokenHash = "a1b2c3d4e5f6..." (never the raw token)
// Only tokenHash stored in DB
```

**Lifecycle:**
1. User requests reset
2. Generate random token + hash
3. Send raw token in email (hashed in DB)
4. User clicks reset link with raw token
5. Hash submitted token, lookup in DB
6. If found and not expired/used: reset password
7. Mark token as used (prevent reuse)
8. Invalidate other pending tokens for user

**Token Expiry:**
- Default: 1 hour
- Not extendable
- Configurable per deployment

```go
cfg.PasswordResetExpiry = 2 * time.Hour // Custom expiry
```

**Prevent Token Reuse:**
```sql
-- Token marked as used after successful reset
UPDATE auth_password_resets
SET used = TRUE
WHERE id = $1;

-- Prevents reuse even if raw token leaked
```

### Password Change vs Reset

**Change Password (User-Initiated):**
- ✅ Requires current password verification
- ✅ User must know old password
- ✅ Session-authenticated
- ✅ No expiry needed

```go
err := store.ChangePassword(ctx, userID, oldPassword, newPassword)
```

**Reset Password (Forgot):**
- ✅ Requires email access only
- ✅ No password knowledge needed
- ✅ Token-authenticated
- ✅ Time-limited

```go
err := store.ResetPassword(ctx, resetToken, newPassword)
```

### Bcrypt Cost Analysis

| Cost | Time | Security | Use Case |
|------|------|----------|----------|
| 8 | ~25ms | Low | Development only |
| 10 | ~100ms | Good | Default production |
| 12 | ~250ms | Very Good | High security needs |
| 14 | ~1000ms | Excellent | Extremely sensitive |

**Recommendation:** Cost 10 (default) balances security and UX.

---

## Token Security

### JWT Implementation

**Algorithm: HMAC-SHA256**
- Symmetric signing (secret used for both sign + verify)
- Fast to verify
- Not suitable for public key distribution

**Token Structure:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  // Header (base64)
.eyJ1c2VyX2lkIjoiMTIzIiwi...            // Claims (base64)
.U8zSVx7j2V0lSQqA8V2x4U9f...            // Signature (HMAC-SHA256)
```

### Token Types

**Access Token (15 minutes default):**
- Short expiry
- Includes permissions (for authorization checks)
- Use in every API request
- Doesn't need re-verification from DB

**Refresh Token (7 days default):**
- Long expiry
- No permissions (just identity)
- Use to request new access token
- Can be stored in persistent cookie
- Never send to client APIs

**Why Separate Tokens?**
- ✅ Access token: Short-lived, can't be used if compromised for long
- ✅ Refresh token: Longer-lived but kept secure (cookie), not sent to APIs
- ✅ Claims: No DB call needed per request (access token)
- ✅ Permissions: Embedded, available immediately

### Token Validation

```go
claims, err := auth.ValidateToken(cfg, tokenStr)
if err != nil {
	// Invalid, expired, or tampered
	return
}

// Token is valid
// Trust claims.UserID, claims.Email, claims.Permissions
```

**Verification includes:**
- ✅ Signature valid (HMAC matches)
- ✅ Not expired (exp claim checked)
- ✅ Well-formed (required fields present)
- ✅ Issued at valid time (iat not in future)

### JWT Secret Management

**Requirements:**
- Minimum 32 characters
- Random/high-entropy
- Unique per deployment
- Never hardcoded in source
- Rotated periodically (carefully)

**Generation:**
```bash
# Generate random secret
openssl rand -base64 32
# Output: dK9j3kL2mN5pQ8rS1uV4wX7yZ0aB3cD6eF9gH2jK5lM8nO1pQ4rS7tU0vW3xY6zA==

# In .env
JWT_SECRET=dK9j3kL2mN5pQ8rS1uV4wX7yZ0aB3cD6eF9gH2jK5lM8nO1pQ4rS7tU0vW3xY6zA==
```

**Environment Loading:**
```go
jwtSecret := os.Getenv("JWT_SECRET")
if jwtSecret == "" || len(jwtSecret) < 32 {
	log.Fatal("JWT_SECRET must be set and >= 32 chars")
}

cfg := auth.DefaultConfig(jwtSecret, adminEmail)
```

### Token Leakage Mitigation

**If access token leaked:**
- ✅ Limited damage (15 min expiry)
- ✅ Refresh new one after expiry
- ✅ No way to forge new tokens without secret

**If refresh token leaked:**
- ✅ Cannot use directly for API access
- ✅ Can only request new access token
- ⚠️ Attacker can impersonate user
- 🔒 Store in httpOnly, secure cookie
- 🔒 Implement revocation if possible

**If JWT secret leaked:**
- 🚨 Attacker can forge any token
- 🚨 Immediate rotation required
- Action:
  1. Deploy new secret
  2. Force all users to re-authenticate
  3. Invalidate old tokens server-side (cache)

---

## Database Security

### Schema Design

**Cascading Deletes:**
```sql
FOREIGN KEY REFERENCES auth_users(id) ON DELETE CASCADE
```

✅ Prevents orphaned records
✅ Maintains referential integrity
✅ No manual cleanup needed

**Unique Constraints:**
```sql
CREATE UNIQUE INDEX idx_auth_users_email ON auth_users(email);
```

✅ Email uniqueness enforced
✅ Prevents duplicate accounts
✅ Quick lookups

**Indices for Performance:**
```sql
CREATE INDEX idx_auth_otps_email ON auth_otps(email);
CREATE INDEX idx_auth_password_resets_hash ON auth_password_resets(token_hash);
CREATE INDEX idx_auth_password_resets_expires ON auth_password_resets(expires_at)
  WHERE used = FALSE;
```

✅ OTP lookup by email
✅ Token validation by hash
✅ Cleanup of expired tokens

### Password Hash Storage

**Column: password_hash (TEXT, NULLABLE)**
- NULL = OTP-only user (can't login with password)
- Non-NULL = Bcrypt hash (starts with $2a$)

```sql
SELECT password_hash FROM auth_users WHERE id = $1;

-- NULL → ErrPasswordNotSet
-- $2a$10$... → password set, can verify
```

### Reset Token Storage

**Never store raw token:**
```
❌ WRONG:
INSERT INTO auth_password_resets (token) VALUES ($1); -- raw token

✅ RIGHT:
tokenHash := HashResetToken(rawToken);
INSERT INTO auth_password_resets (token_hash) VALUES ($1); -- hash only
```

**Verify by hash:**
```go
submittedHash := HashResetToken(submittedToken)
// SELECT ... WHERE token_hash = submittedHash
// Compare: if found, token is valid
```

### Database Connection Security

**Connection String:**
```
postgresql://user:password@localhost:5432/authdb
```

**Security:**
- ✅ Use HTTPS/TLS for remote connections
- ✅ Require strong database passwords
- ✅ Limit database user permissions (read+write only needed tables)
- ✅ Don't expose connection string in logs
- ✅ Use environment variables

**PostgreSQL Config:**
```bash
# .env (never commit to repo)
DATABASE_URL=postgresql://user:password@host:5432/authdb?sslmode=require
```

```go
// Load from env
databaseURL := os.Getenv("DATABASE_URL")
pool, err := pgxpool.New(ctx, databaseURL)
```

### SQL Injection Prevention

**Parameterized Queries (Used Throughout):**
```go
// ✅ SAFE - Parameter binding
err := db.QueryRow(ctx,
	"SELECT * FROM auth_users WHERE email = $1",
	email,
).Scan(...)

// ❌ UNSAFE - String concatenation
query := fmt.Sprintf("SELECT * FROM auth_users WHERE email = '%s'", email)
err := db.QueryRow(ctx, query).Scan(...)
```

All auth v2 queries use parameterized statements automatically.

---

## API Security

### Authentication Middleware

```go
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// Parse Bearer scheme
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid format", http.StatusUnauthorized)
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
```

### Authorization Checks

**Check Claims Before Action:**
```go
claims := r.Context().Value("claims").(*auth.Claims)

// Check permission
canCreate := false
for _, perm := range claims.Permissions {
	if perm == "forms:create" {
		canCreate = true
		break
	}
}

if !canCreate {
	http.Error(w, "Forbidden", http.StatusForbidden)
	return
}

// Allowed to create
```

**Better Pattern (Helper Function):**
```go
func hasPerm(claims *auth.Claims, perm string) bool {
	for _, p := range claims.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// Usage
if !hasPerm(claims, "forms:create") {
	http.Error(w, "Forbidden", http.StatusForbidden)
	return
}
```

### HTTPS Only

**Requirements:**
- ✅ All password/token transmission over HTTPS
- ✅ Redirect HTTP → HTTPS
- ✅ HSTS header for browsers
- ✅ Secure cookie flags

```go
// Redirect HTTP to HTTPS
http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}))

// HTTPS with TLS
http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
```

### Cookie Security

**For Refresh Tokens:**
```go
http.SetCookie(w, &http.Cookie{
	Name:     "refresh_token",
	Value:    refreshToken,
	Path:     "/",
	HttpOnly: true,        // ✓ Can't access from JavaScript
	Secure:   true,        // ✓ HTTPS only
	SameSite: http.SameSiteLaxMode, // ✓ CSRF protection
	MaxAge:   7 * 24 * 3600, // 7 days
})
```

### Rate Limiting

**Recommended Endpoints to Rate Limit:**
- ✅ POST /auth/login - 5 attempts per minute per IP
- ✅ POST /auth/register - 10 per minute per IP
- ✅ POST /auth/otp - 5 per minute per email
- ✅ POST /auth/password-reset - 3 per hour per email

```go
// Example with rate limiting
limiter := rate.NewLimiter(rate.Every(time.Minute/5), 1) // 5 per minute

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !limiter.Allow() {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// ... login logic
}
```

### Input Validation

**Email Validation:**
```go
// Use email parsing
addr, err := mail.ParseAddress(email)
if err != nil {
	http.Error(w, "Invalid email", http.StatusBadRequest)
	return
}

// addr.Address is normalized
```

**Password Validation:**
```go
err := auth.ValidatePasswordStrength(cfg, password)
if err != nil {
	http.Error(w, "Password too weak", http.StatusBadRequest)
	return
}
```

### Error Messages

**Don't Leak Information:**
```go
// ✅ SAFE - Generic message
if err := auth.CheckPassword(input, hash); err != nil {
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// ❌ UNSAFE - Reveals user existence
if user == nil {
	http.Error(w, "User not found", http.StatusNotFound)
} else if err := auth.CheckPassword(input, hash); err != nil {
	http.Error(w, "Wrong password", http.StatusUnauthorized)
}
```

---

## Email Security

### API Key Protection

**ZeptoMail API Key:**
- Never commit to repository
- Never log in output
- Load from environment only
- Rotate periodically

```go
// ✅ SAFE
apiKey := os.Getenv("ZEPTO_API_KEY")

// ❌ UNSAFE
const apiKey = "PHtE6r0K..." // Hardcoded!
log.Printf("Sending with key: %s", apiKey) // Logged!
```

### Email Templates

**Password Reset Email:**
- HTML email with branding
- Clickable button + fallback text link
- Clear expiry warning
- "If you didn't request this..." disclaimer

### Link in Email

**Reset URL Format:**
```
https://example.com/reset?token=<BASE64_ENCODED_TOKEN>
```

✅ Token in query parameter (safe, HTTPS encrypted)
✅ Single-use token
✅ Expiration time limited
✅ User feedback in email

### Phishing Prevention

**Email Best Practices:**
- ✅ Brand consistently
- ✅ Clear sender identity
- ✅ No requests for password in email
- ✅ Links point to verified domain
- ✅ DKIM/SPF/DMARC for email authentication

---

## Configuration Security

### Environment Variables

**Required:**
```bash
JWT_SECRET=<32+ chars random>
DATABASE_URL=postgresql://...
ZEPTO_API_KEY=<api-key>
FROM_EMAIL=noreply@example.com
SUPER_ADMIN_EMAIL=admin@example.com
```

**Never in Code:**
```
❌ config.json with secrets
❌ Hardcoded constants
❌ Version control committed
```

### Secrets Management

**Production:**
- Use secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- Inject at runtime
- Rotate on schedule
- Audit access

**Development:**
```bash
# Create .env file (git-ignored)
# Load via github.com/joho/godotenv or similar
```

### Logging

**What NOT to Log:**
- ❌ Passwords (plain or hashed)
- ❌ Tokens (JWT or reset)
- ❌ API keys
- ❌ Email addresses (in some contexts)
- ❌ User IDs for sensitive operations

**What IS SAFE to Log:**
- ✅ Authentication events (user X logged in)
- ✅ Permission checks (access denied for resource Y)
- ✅ Error types (invalid credentials, not passwords)
- ✅ Hashed identifiers
- ✅ Timestamps and IPs for audit

---

## Common Vulnerabilities

### Timing Attacks

**bcrypt.CompareHashAndPassword is safe:**
```go
// ✅ SAFE - Constant-time comparison
err := auth.CheckPassword(input, hash)

// ❌ UNSAFE - String comparison reveals timing info
if input == password {
```

### Brute Force Attacks

**Mitigations:**
- ✅ Rate limiting per IP
- ✅ Rate limiting per email
- ✅ Exponential backoff
- ✅ Account lockout (careful - DOS vector)
- ✅ CAPTCHA for multiple failures

### Session Fixation

**Not applicable** - Using stateless JWT tokens, not session cookies.

### CSRF Protection

**If using cookies for tokens:**
```go
// Require token in request body/header for state-changing operations
http.SetCookie(w, &http.Cookie{
	SameSite: http.SameSiteLaxMode, // CSRF protection
	HttpOnly: true,                  // XSS protection
	Secure:   true,                  // HTTPS only
})
```

### XSS Prevention

**Never trust user input in templates:**
```go
// ✅ SAFE - Auto-escapes
template.HTML(`<p>{{.UserInput}}</p>`) // Automatically escaped

// ❌ UNSAFE - No escaping
fmt.Sprintf(`<p>%s</p>`, userInput) // Direct output
```

### SQL Injection

**All queries are parameterized:**
```go
// ✅ SAFE - Parameterized
db.QueryRow(ctx, "SELECT * FROM users WHERE email = $1", email)

// Confirmed: All auth v2 queries use parameterization
```

---

## Security Checklist

### Before Deployment

- [ ] JWT_SECRET is 32+ random characters
- [ ] JWT_SECRET not in code/logs
- [ ] HTTPS enforced (redirect HTTP)
- [ ] Database password is strong
- [ ] Database connection uses SSL/TLS
- [ ] Bcrypt cost appropriate for hardware
- [ ] Password strength enforced
- [ ] Rate limiting configured
- [ ] Logging doesn't leak secrets
- [ ] Error messages don't leak info
- [ ] Refresh token in httpOnly cookie
- [ ] Access token in memory/header
- [ ] CORS configured correctly
- [ ] HSTS header enabled
- [ ] Database backups working
- [ ] Monitoring/alerting in place

### Regular Reviews

- [ ] Dependency updates for security patches
- [ ] Bcrypt cost evaluation (GPU evolution)
- [ ] JWT secret rotation plan
- [ ] Database audit logs
- [ ] Failed login attempts spike
- [ ] New permission requirements

### Incident Response

**If compromised:**
1. Rotate JWT_SECRET immediately
2. Invalidate all active tokens
3. Force password reset for users
4. Review audit logs
5. Check database for tampering
6. Notify users

---

## Additional Resources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Bcrypt Algorithm](https://en.wikipedia.org/wiki/Bcrypt)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/sql-syntax.html)
