package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	auth "github.com/meikuraledutech/auth/v2"
	"github.com/meikuraledutech/auth/v2/postgres"
	"github.com/meikuraledutech/mailing"
	mailingzepto "github.com/meikuraledutech/mailing/zeptomail"
)

// AppMailer implements auth.Mailer using mailing.Sender.
// Each app brings their own templates and sender identity.
type AppMailer struct {
	sender    mailing.Sender
	apiKey    string
	fromEmail string
}

func (m *AppMailer) SendOTP(ctx context.Context, email string, code string, expiresIn time.Duration) error {
	html := fmt.Sprintf(`
		<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
			<h2>Your verification code</h2>
			<p style="font-size:32px;font-weight:bold;letter-spacing:8px">%s</p>
			<p style="color:#666">Expires in %d minutes.</p>
		</div>`, code, int(expiresIn.Minutes()))

	_, err := m.sender.Send(ctx, mailing.Mail{
		Token:   m.apiKey,
		From:    m.fromEmail,
		To:      email,
		Subject: "Your Smart Forms verification code",
		HTML:    html,
	})
	return err
}

func (m *AppMailer) SendPasswordReset(ctx context.Context, email string, resetURL string, expiresIn time.Duration) error {
	html := fmt.Sprintf(`
		<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
			<h2>Reset your password</h2>
			<p>Click the button below to reset your password. This link expires in %d minutes.</p>
			<a href="%s" style="display:inline-block;padding:12px 24px;background:#0070f3;color:#fff;text-decoration:none;border-radius:6px">Reset Password</a>
			<p style="color:#666;font-size:12px">Or copy this link: %s</p>
		</div>`, int(expiresIn.Minutes()), resetURL, resetURL)

	_, err := m.sender.Send(ctx, mailing.Mail{
		Token:   m.apiKey,
		From:    m.fromEmail,
		To:      email,
		Subject: "Reset your Smart Forms password",
		HTML:    html,
	})
	return err
}

func (m *AppMailer) SendWelcome(ctx context.Context, user *auth.User) error {
	html := fmt.Sprintf(`
		<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
			<h2>Welcome to Smart Forms!</h2>
			<p>Hi %s,</p>
			<p>Your account has been created. Start building your forms today.</p>
			<a href="https://smart-forms.in/dashboard" style="display:inline-block;padding:12px 24px;background:#0070f3;color:#fff;text-decoration:none;border-radius:6px">Go to Dashboard</a>
		</div>`, user.Email)

	_, err := m.sender.Send(ctx, mailing.Mail{
		Token:   m.apiKey,
		From:    m.fromEmail,
		To:      user.Email,
		Subject: "Welcome to Smart Forms!",
		HTML:    html,
	})
	return err
}

func main() {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	zeptoAPIKey := os.Getenv("ZEPTO_API_KEY")
	zeptoAPIURL := os.Getenv("ZEPTO_API_URL")
	zeptoProvider := os.Getenv("ZEPTO_PROVIDER")
	fromEmail := os.Getenv("FROM_EMAIL")
	superAdminEmail := os.Getenv("SUPER_ADMIN_EMAIL")

	if databaseURL == "" {
		log.Fatalf("DATABASE_URL not set")
	}
	if jwtSecret == "" {
		jwtSecret = "test-secret-key"
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	cfg := auth.DefaultConfig(jwtSecret, superAdminEmail)

	sender := mailingzepto.New(mailingzepto.Config{
		APIURL:   zeptoAPIURL,
		Provider: zeptoProvider,
	})
	mailer := &AppMailer{sender: sender, apiKey: zeptoAPIKey, fromEmail: fromEmail}

	store := postgres.New(pool, cfg)

	fmt.Println("=== Testing Auth v2 ===\n")

	// 1: Bootstrap
	fmt.Println("1. Running migrations and bootstrap...")
	if err := store.Bootstrap(ctx, superAdminEmail); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}
	fmt.Println("   ✓ Bootstrap complete\n")

	// 2: Create OTP
	testEmail := "dharaniadithya1998.da@gmail.com"
	fmt.Printf("2. Creating OTP for %s...\n", testEmail)
	otp, err := store.CreateOTP(ctx, testEmail)
	if err != nil {
		log.Fatalf("CreateOTP failed: %v", err)
	}
	fmt.Printf("   ✓ OTP created: %s\n", otp.Code)

	// 3: Send OTP email
	fmt.Println("3. Sending OTP email...")
	if err := mailer.SendOTP(ctx, testEmail, otp.Code, cfg.OTPExpiry); err != nil {
		log.Fatalf("SendOTP failed: %v", err)
	}
	fmt.Printf("   ✓ OTP email sent to %s\n\n", testEmail)

	// 4: Password register — triggers SendWelcome automatically
	testPassword := "TestPassword123!"
	regEmail := "dharaniadithya1998.da@gmail.com"
	fmt.Printf("4. Registering user with password (%s)...\n", regEmail)
	user, err := store.RegisterWithPassword(ctx, regEmail, testPassword)
	if err != nil {
		log.Fatalf("RegisterWithPassword failed: %v", err)
	}
	fmt.Printf("   ✓ User registered: %s\n", user.Email)

	// App decides when/whether to send welcome — library does not auto-trigger
	if err := mailer.SendWelcome(ctx, user); err != nil {
		log.Fatalf("SendWelcome failed: %v", err)
	}
	fmt.Printf("   ✓ Welcome email sent\n\n")

	// 5: Login with password
	fmt.Println("5. Logging in with password...")
	loggedIn, err := store.LoginWithPassword(ctx, regEmail, testPassword)
	if err != nil {
		log.Fatalf("LoginWithPassword failed: %v", err)
	}
	fmt.Printf("   ✓ Logged in: %s\n\n", loggedIn.Email)

	// 6: Password reset token
	fmt.Println("6. Creating password reset token...")
	resetToken, expiresAt, err := store.CreatePasswordReset(ctx, regEmail)
	if err != nil {
		log.Fatalf("CreatePasswordReset failed: %v", err)
	}
	fmt.Printf("   ✓ Reset token created, expires: %s\n", expiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   ✓ Token: %s...\n\n", resetToken[:20])

	// 7: Generate JWT token pair
	fmt.Println("7. Generating JWT token pair...")
	tokens, err := auth.GenerateTokenPair(cfg, user, []string{}, []string{})
	if err != nil {
		log.Fatalf("GenerateTokenPair failed: %v", err)
	}
	fmt.Printf("   ✓ Access token:  %s...\n", tokens.AccessToken[:50])
	fmt.Printf("   ✓ Refresh token: %s...\n\n", tokens.RefreshToken[:50])

	// 8: Refresh token pair
	fmt.Println("8. Refreshing token pair...")
	newTokens, err := auth.RefreshTokenPair(ctx, cfg, store, tokens.RefreshToken)
	if err != nil {
		log.Fatalf("RefreshTokenPair failed: %v", err)
	}
	fmt.Printf("   ✓ New access token:  %s...\n", newTokens.AccessToken[:50])
	fmt.Printf("   ✓ New refresh token: %s...\n\n", newTokens.RefreshToken[:50])

	fmt.Println("=== All tests passed! ===")
	fmt.Printf("\nOTP code: %s (sent to %s)\n", otp.Code, testEmail)
}
