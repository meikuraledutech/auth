package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	auth "github.com/meikuraledutech/auth/v2"
	"github.com/meikuraledutech/auth/v2/postgres"
	"github.com/meikuraledutech/auth/v2/zeptomail"
)

func main() {
	ctx := context.Background()

	// Load config from environment
	databaseURL := os.Getenv("DATABASE_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	zeptoAPIKey := os.Getenv("ZEPTO_API_KEY")
	fromEmail := os.Getenv("FROM_EMAIL")
	superAdminEmail := os.Getenv("SUPER_ADMIN_EMAIL")

	if databaseURL == "" {
		log.Fatalf("DATABASE_URL not set")
	}
	if jwtSecret == "" {
		jwtSecret = "test-secret-key"
	}

	// Connect to database
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	// Create auth config
	cfg := auth.DefaultConfig(jwtSecret, superAdminEmail)

	// Create store and mailer
	store := postgres.New(pool, cfg)
	mailer := zeptomail.New(zeptoAPIKey, fromEmail)

	fmt.Println("=== Testing Auth v2 ===\n")

	// Test 1: Bootstrap
	fmt.Println("1. Running migrations and bootstrap...")
	if err := store.Bootstrap(ctx, superAdminEmail); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}
	fmt.Println("   ✓ Bootstrap complete\n")

	// Test 2: Send OTP
	testEmail := "dharaniadithya1998.da@gmail.com"
	fmt.Printf("2. Creating OTP for %s...\n", testEmail)
	otp, err := store.CreateOTP(ctx, testEmail)
	if err != nil {
		log.Fatalf("CreateOTP failed: %v", err)
	}
	fmt.Printf("   ✓ OTP created: %s\n", otp.Code)

	// Test 3: Send OTP email
	fmt.Println("3. Sending OTP email...")
	if err := mailer.SendOTP(ctx, testEmail, otp.Code, cfg.OTPExpiry); err != nil {
		log.Fatalf("SendOTP failed: %v", err)
	}
	fmt.Printf("   ✓ Email sent to %s with code: %s\n\n", testEmail, otp.Code)

	// Test 4: Test password auth
	fmt.Println("4. Testing password auth...")
	testPassword := "TestPassword123!"

	// Register with password
	fmt.Printf("   - Registering user with password...\n")
	user, err := store.RegisterWithPassword(ctx, "password.user@example.com", testPassword)
	if err != nil {
		log.Fatalf("RegisterWithPassword failed: %v", err)
	}
	fmt.Printf("     ✓ User registered: %s\n", user.Email)

	// Login with password
	fmt.Printf("   - Logging in with password...\n")
	loggedInUser, err := store.LoginWithPassword(ctx, "password.user@example.com", testPassword)
	if err != nil {
		log.Fatalf("LoginWithPassword failed: %v", err)
	}
	fmt.Printf("     ✓ Logged in: %s\n\n", loggedInUser.Email)

	// Test 5: Password reset
	fmt.Println("5. Testing password reset...")
	resetToken, expiresAt, err := store.CreatePasswordReset(ctx, "password.user@example.com")
	if err != nil {
		log.Fatalf("CreatePasswordReset failed: %v", err)
	}
	fmt.Printf("   ✓ Reset token created, expires at: %s\n", expiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   ✓ Raw token (for reset link): %s\n\n", resetToken)

	// Test 6: Generate token pair
	fmt.Println("6. Testing token generation...")
	tokens, err := auth.GenerateTokenPair(cfg, user, []string{}, []string{})
	if err != nil {
		log.Fatalf("GenerateTokenPair failed: %v", err)
	}
	fmt.Printf("   ✓ Access token: %s...\n", tokens.AccessToken[:50])
	fmt.Printf("   ✓ Refresh token: %s...\n\n", tokens.RefreshToken[:50])

	fmt.Println("=== All tests passed! ===")
	fmt.Printf("\nOTP Code to verify: %s\n", otp.Code)
	fmt.Printf("OTP sent to: %s\n", testEmail)
}
