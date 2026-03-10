# Mailing Integration

**Version:** auth/v2 — v2.0.3
**Mailing package:** `github.com/meikuraledutech/mailing` v0.0.1
**Breaking change:** `v2/zeptomail` package removed — apps must implement `auth.Mailer` themselves

---

## What Changed in v2.0.3

| Before (v2.0.2) | After (v2.0.3) |
|-----------------|----------------|
| `v2/zeptomail` package included in auth repo | Removed — app-level concern |
| Hardcoded ZeptoMail templates inside the library | App owns all templates and sender identity |
| `Mailer` interface had `SendOTP` + `SendPasswordReset` | Added `SendWelcome(ctx, *User) error` |
| `SendWelcome` auto-triggered by library | Never auto-triggered — app calls it when ready |

---

## Dependencies

Add to your app's `go.mod`:

```bash
go get github.com/meikuraledutech/auth/v2@v2.0.3
go get github.com/meikuraledutech/mailing@v0.0.1
```

auth/v2 itself has **zero dependency** on the mailing package.

---

## Mailer Interface

```go
// github.com/meikuraledutech/auth/v2
type Mailer interface {
    SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error
    SendPasswordReset(ctx context.Context, email string, resetURL string, expiresIn time.Duration) error
    SendWelcome(ctx context.Context, user *User) error
}
```

Your app implements this interface. The library calls `SendOTP` and `SendPasswordReset` when it needs to notify the caller — but `SendWelcome` is **never called by the library**. Your app decides when to call it.

---

## Environment Variables

```env
ZEPTO_API_KEY=<your-zeptomail-api-key>
ZEPTO_API_URL=https://api.zeptomail.in/v1.1/email
ZEPTO_PROVIDER=zeptomail
FROM_EMAIL=noreply@yourdomain.com
```

---

## Implementation

### Step 1 — Create your Mailer struct

```go
import (
    auth "github.com/meikuraledutech/auth/v2"
    "github.com/meikuraledutech/mailing"
    mailingzepto "github.com/meikuraledutech/mailing/zeptomail"
)

type AppMailer struct {
    sender    mailing.Sender
    apiKey    string
    fromEmail string
}

func NewAppMailer(apiKey, apiURL, provider, fromEmail string) *AppMailer {
    return &AppMailer{
        sender: mailingzepto.New(mailingzepto.Config{
            APIURL:   apiURL,
            Provider: provider,
        }),
        apiKey:    apiKey,
        fromEmail: fromEmail,
    }
}
```

### Step 2 — Implement each method

```go
func (m *AppMailer) SendOTP(ctx context.Context, email, code string, expiresIn time.Duration) error {
    _, err := m.sender.Send(ctx, mailing.Mail{
        Token:   m.apiKey,
        From:    m.fromEmail,
        To:      email,
        Subject: "Your verification code",
        HTML:    fmt.Sprintf(`<p>Your code: <strong>%s</strong>. Expires in %d minutes.</p>`, code, int(expiresIn.Minutes())),
    })
    return err
}

func (m *AppMailer) SendPasswordReset(ctx context.Context, email, resetURL string, expiresIn time.Duration) error {
    _, err := m.sender.Send(ctx, mailing.Mail{
        Token:   m.apiKey,
        From:    m.fromEmail,
        To:      email,
        Subject: "Reset your password",
        HTML:    fmt.Sprintf(`<p>Reset your password: <a href="%s">Click here</a>. Expires in %d minutes.</p>`, resetURL, int(expiresIn.Minutes())),
    })
    return err
}

func (m *AppMailer) SendWelcome(ctx context.Context, user *auth.User) error {
    _, err := m.sender.Send(ctx, mailing.Mail{
        Token:   m.apiKey,
        From:    m.fromEmail,
        To:      user.Email,
        Subject: "Welcome!",
        HTML:    fmt.Sprintf(`<p>Hi %s, welcome! Your account is ready.</p>`, user.Email),
    })
    return err
}
```

### Step 3 — Wire up and use

```go
store  := postgres.New(pool, cfg)
mailer := NewAppMailer(
    os.Getenv("ZEPTO_API_KEY"),
    os.Getenv("ZEPTO_API_URL"),
    os.Getenv("ZEPTO_PROVIDER"),
    os.Getenv("FROM_EMAIL"),
)

// --- OTP flow ---
otp, err := store.CreateOTP(ctx, email)
mailer.SendOTP(ctx, email, otp.Code, cfg.OTPExpiry)

user, err := store.VerifyOTP(ctx, email, code)
// app decides: is this a new user? send welcome?
mailer.SendWelcome(ctx, user)

// --- Password flow ---
user, err := store.RegisterWithPassword(ctx, email, password)
mailer.SendWelcome(ctx, user) // call here or after profile setup — your choice

// --- Password reset flow ---
rawToken, expiresAt, err := store.CreatePasswordReset(ctx, email)
resetURL := "https://yourdomain.com/reset?token=" + rawToken
mailer.SendPasswordReset(ctx, email, resetURL, cfg.PasswordResetExpiry)

err = store.ResetPassword(ctx, rawToken, newPassword)
```

---

## mailing.Mail Fields

| Field | Type | Description |
|-------|------|-------------|
| `Token` | string | Provider API key. For ZeptoMail: the `Zoho-enczapikey` value |
| `From` | string | Sender address — must be verified in your ZeptoMail account |
| `To` | string | Recipient address |
| `Subject` | string | Email subject line |
| `HTML` | string | Full HTML email body |

`mailing.Sender.Send()` returns `(mailing.Status, error)`. Discard `Status` if you don't need tracking, or pass it to `mailing.Store` to record the send in PostgreSQL.

---

## ZeptoMail API Response

A successful send returns HTTP 200 with:

```json
{
  "data": [{ "code": "EM_104", "message": "Email request received" }],
  "message": "OK",
  "request_id": "...",
  "object": "email"
}
```

`EM_104` — email accepted for delivery. `mailing.Status.Status` will be `"queued"`.

---

## Reusing mailing.Sender for Non-Auth Emails

Since `mailing` is your app's dependency, the same sender works for all transactional emails:

```go
// auth emails
authMailer := NewAppMailer(...)

// other app emails — reuse the same sender
sender.Send(ctx, mailing.Mail{
    Token:   apiKey,
    From:    fromEmail,
    To:      user.Email,
    Subject: "Your form received a new response",
    HTML:    "...",
})
```

---

## Why Was v2/zeptomail Removed?

The old `v2/zeptomail` package was a hardcoded implementation inside the auth library. It was removed because:

1. **Sender identity** — different apps using auth/v2 have different from-addresses and domains
2. **Template ownership** — each app needs its own branding for OTP, welcome, and reset emails
3. **Provider flexibility** — not all apps use ZeptoMail; some use SES, SendGrid, Resend, etc.
4. **Trigger control** — `SendWelcome` timing is a business decision that belongs in the app, not the library
5. **Zero dependency** — auth/v2 stays lean with no email provider dependency

---

## Migration from v2.0.2

If you were using `github.com/meikuraledutech/auth/v2/zeptomail`:

1. Remove the import
2. Install `github.com/meikuraledutech/mailing@v0.0.1`
3. Create an `AppMailer` struct implementing `auth.Mailer` (see Step 1–2 above)
4. Add `SendWelcome` to your mailer implementation
5. Call `mailer.SendWelcome(ctx, user)` manually after registration/OTP verify
