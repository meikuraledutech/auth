# Auth v2 - Documentation Index

Complete documentation for the auth v2 module. **Start here!**

## Quick Links

| Document | Purpose | For Whom |
|----------|---------|----------|
| [GETTING_STARTED.md](./GETTING_STARTED.md) | 5-minute setup guide | New users, developers |
| [README.md](./README.md) | Complete feature overview | Everyone |
| [STORE_API.md](./STORE_API.md) | Full API reference | Developers implementing features |
| [HELPERS.md](./HELPERS.md) | Password & token helpers | Developers using utilities |
| [SECURITY.md](./SECURITY.md) | Security best practices | Security-conscious teams, DevOps |

---

## Documentation Overview

### [GETTING_STARTED.md](./GETTING_STARTED.md)
**~250 lines | 5-10 minute read**

Start here if you're new. Covers:
- Prerequisites and setup
- Environment variables configuration
- Database initialization
- 4 HTTP endpoints (OTP, password, reset)
- Middleware for route protection
- Common tasks and quick examples
- Troubleshooting guide

**Best for:** First-time setup, rapid integration

---

### [README.md](./README.md)
**~600 lines | 15-20 minute read**

Comprehensive guide covering:
- Feature overview with emoji indicators
- Installation and quick start
- Detailed authentication methods (OTP, password, reset)
- Configuration and environment variables
- Permission and group management
- JWT token usage
- Database schema with all tables
- Error handling patterns
- Migration from v1
- Testing instructions

**Best for:** Understanding capabilities, implementation reference

---

### [STORE_API.md](./STORE_API.md)
**~900 lines | Complete API reference**

Exhaustive method documentation:
- **Schema Management** (2 methods)
  - CreateSchema, DropSchema
- **OTP Authentication** (2 methods)
  - CreateOTP, VerifyOTP
- **User Management** (4 methods)
  - CreateUser, GetUserByID, GetUserByEmail, ListUsers
- **Password Authentication** (5 methods)
  - RegisterWithPassword, LoginWithPassword, SetPassword, ChangePassword, HasPassword
- **Password Reset** (2 methods)
  - CreatePasswordReset, ResetPassword
- **Permission Management** (10 methods)
  - Create, Get, List, Delete, Assign, Revoke, HasPermission, GetResolvedPermissions, HasResolvedPermission
- **Group Management** (8 methods)
  - Create, Get, List, Delete, Add/Remove Permissions, Assign/Remove Users
- **Bootstrap & Migration** (4 methods)
  - Bootstrap, Migrate, Rollback, MigrationStatus

Each method includes:
- Complete signature
- Parameter descriptions
- Return values and error types
- Real-world usage examples
- Error handling patterns

**Best for:** API reference while coding, understanding method contracts

---

### [HELPERS.md](./HELPERS.md)
**~700 lines | Password & token utilities guide**

Helper function documentation:
- **Password Helpers** (3 functions)
  - HashPassword - Validate & hash with bcrypt
  - CheckPassword - Verify against hash
  - ValidatePasswordStrength - Check requirements
- **Token Helpers** (2 functions)
  - GenerateResetToken - CSPRNG for resets
  - HashResetToken - SHA-256 one-way hash
- **JWT Functions** (2 functions)
  - GenerateTokenPair - Create access + refresh
  - ValidateToken - Parse & verify JWT

For each:
- Purpose and security rationale
- Parameters and return values
- Real-world examples
- Usage patterns
- Why this design choice

**Bonus:** Complete flow examples
- Login flow (8 steps)
- Password reset flow (2 steps)
- Security best practices (10 patterns)

**Best for:** Understanding password security, token handling

---

### [SECURITY.md](./SECURITY.md)
**~1200 lines | Security guide & best practices**

Comprehensive security manual:
- **Password Security**
  - Hashing algorithm (bcrypt) rationale
  - Strength validation rules
  - Reset token generation & storage
  - Cost analysis (time vs security tradeoff)
- **Token Security**
  - JWT implementation details
  - Access vs refresh token distinction
  - Secret management
  - Leakage mitigation
- **Database Security**
  - Schema design (cascading, constraints)
  - Password hash storage
  - Reset token storage
  - SQL injection prevention
- **API Security**
  - Authentication middleware
  - Authorization checks
  - HTTPS enforcement
  - Rate limiting
  - Input validation
  - Error message guidelines
- **Email Security**
  - API key protection
  - Email template best practices
  - Phishing prevention
- **Configuration Security**
  - Environment variables
  - Secrets management
  - Logging guidelines
- **Common Vulnerabilities**
  - Timing attacks (prevention)
  - Brute force (mitigation)
  - CSRF, XSS, SQL injection (protection)
- **Security Checklist**
  - Pre-deployment checklist
  - Regular review items
  - Incident response plan

**Best for:** Security audits, production deployment, security training

---

## Learning Path

### Path 1: Quick Integration (30 minutes)
1. Read [GETTING_STARTED.md](./GETTING_STARTED.md) (5-10 min)
2. Copy example code to your project (10 min)
3. Run tests to verify (5 min)
4. Reference [STORE_API.md](./STORE_API.md) as needed (10 min)

### Path 2: Deep Understanding (2-3 hours)
1. Read [README.md](./README.md) (20 min) - Overview
2. Read [GETTING_STARTED.md](./GETTING_STARTED.md) (10 min) - Setup
3. Study [STORE_API.md](./STORE_API.md) (30 min) - Full API
4. Study [HELPERS.md](./HELPERS.md) (30 min) - Security functions
5. Review [SECURITY.md](./SECURITY.md) (45 min) - Best practices

### Path 3: Security Hardening (1-2 hours)
1. Read relevant section in [SECURITY.md](./SECURITY.md) (30 min)
2. Review security checklist (15 min)
3. Implement recommendations (45+ min)
4. Test with security tools

### Path 4: Reference Lookup (as needed)
1. [README.md](./README.md) - Feature overview
2. [STORE_API.md](./STORE_API.md) - Method details
3. [HELPERS.md](./HELPERS.md) - Function behavior
4. [SECURITY.md](./SECURITY.md) - Security details

---

## Key Concepts

### Authentication Methods

**OTP (One-Time Password)**
- 6-digit code sent via email
- 5-minute expiry
- Auto-creates user on first verify
- No password required
- Good for initial account creation

**Password**
- Bcrypt hashed with salt
- 8-72 character length
- Requires uppercase, lowercase, digit, special char
- Fast login after initial setup
- Password reset via email

### Permission Model

**Direct Permissions**
- Assigned directly to user
- Checked with HasPermission
- Immediately effective

**Group Permissions**
- User belongs to groups
- Groups have permissions
- Checked with HasResolvedPermission
- Inherited automatically

### Token Types

**Access Token** (15 min default)
- Short expiry
- Contains permissions
- Used for API requests
- Can't be used if compromised for long

**Refresh Token** (7 days default)
- Long expiry
- No permissions
- Gets new access tokens
- Kept secure in httpOnly cookie

### Password Reset

**Flow:**
1. User requests reset → CreatePasswordReset returns token
2. Token hashed and stored in DB
3. Raw token sent in email reset link
4. User submits token + new password
5. Hash submitted token, verify against DB
6. If valid: update password + mark token used

**Security:**
- Only hash stored (raw token not recoverable)
- Single-use (marked after successful use)
- Time-limited (expires in 1 hour)
- Invalidates previous tokens

---

## Code Examples by Use Case

### I want to...

**Let user register with email/password**
→ [GETTING_STARTED.md](./GETTING_STARTED.md) - handleRegister
→ [STORE_API.md](./STORE_API.md) - RegisterWithPassword

**Let user login**
→ [GETTING_STARTED.md](./GETTING_STARTED.md) - handleLogin
→ [STORE_API.md](./STORE_API.md) - LoginWithPassword

**Send OTP code**
→ [GETTING_STARTED.md](./GETTING_STARTED.md) - handleRequestOTP
→ [STORE_API.md](./STORE_API.md) - CreateOTP

**Verify OTP and create tokens**
→ [GETTING_STARTED.md](./GETTING_STARTED.md) - handleVerifyOTP
→ [STORE_API.md](./STORE_API.md) - VerifyOTP

**Handle password reset**
→ [GETTING_STARTED.md](./GETTING_STARTED.md) - handleForgotPassword/handleResetPassword
→ [HELPERS.md](./HELPERS.md) - Complete Password Reset Flow

**Check user permissions**
→ [README.md](./README.md) - Permission & Group Management
→ [STORE_API.md](./STORE_API.md) - HasResolvedPermission

**Protect API routes**
→ [GETTING_STARTED.md](./GETTING_STARTED.md) - authMiddleware
→ [HELPERS.md](./HELPERS.md) - Validate Token example

**Manage user groups**
→ [README.md](./README.md) - Groups section
→ [STORE_API.md](./STORE_API.md) - Group Management methods

**Deploy securely**
→ [SECURITY.md](./SECURITY.md) - Security Checklist
→ [SECURITY.md](./SECURITY.md) - Configuration Security

---

## File Statistics

```
README.md          ~600 lines - Feature overview + quick start
GETTING_STARTED.md ~250 lines - Setup guide + examples
STORE_API.md       ~900 lines - Complete API reference
HELPERS.md         ~700 lines - Helper functions + patterns
SECURITY.md        ~1200 lines - Security guide + best practices
DOCS_INDEX.md      ~400 lines - This file

Total: ~4,050 lines of documentation
```

---

## FAQ

**Q: Which document should I read first?**
A: Start with [GETTING_STARTED.md](./GETTING_STARTED.md) if you're new, or [README.md](./README.md) for complete overview.

**Q: Where do I find API method details?**
A: [STORE_API.md](./STORE_API.md) has exhaustive documentation for every method.

**Q: How do I handle passwords securely?**
A: Read [SECURITY.md](./SECURITY.md) - Password Security section.

**Q: What's the difference between access and refresh tokens?**
A: [README.md](./README.md) - JWT Token Usage or [HELPERS.md](./HELPERS.md) - JWT Functions section.

**Q: How do I implement password reset?**
A: [GETTING_STARTED.md](./GETTING_STARTED.md) - handleForgotPassword/handleResetPassword, or [HELPERS.md](./HELPERS.md) - Complete Password Reset Flow.

**Q: What permissions do I need?**
A: Design your permission keys (e.g., "forms:create", "users:manage"). See [README.md](./README.md) - Permission & Group Management.

**Q: How do I check if user can do something?**
A: Use store.HasResolvedPermission(). See [STORE_API.md](./STORE_API.md) - HasResolvedPermission.

**Q: Can I use this with existing OTP-only users?**
A: Yes! Password auth is optional. See [README.md](./README.md) - Migration from v1.

---

## Contributing

Found errors or want to improve docs? Issues and PRs welcome!

---

## Related Resources

- [Auth v2 Repository](https://github.com/meikuraledutech/auth)
- [OAuth 2.0 Spec](https://tools.ietf.org/html/rfc6749)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Security Guides](https://cheatsheetseries.owasp.org/)
- [Bcrypt Paper](https://www.usenix.org/conference/usenix-security-99/provably-secure-password-hashing-algorithm)

---

**Last Updated:** 2026-03-05

**Documentation Version:** 1.0

**Auth v2 Version:** 2.0.0
