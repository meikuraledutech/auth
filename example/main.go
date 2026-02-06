package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meikuraledutech/auth"
	"github.com/meikuraledutech/auth/postgres"
	"github.com/meikuraledutech/auth/zeptomail"
)

func main() {
	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set")
	}
	zeptoKey := os.Getenv("ZEPTO_API_KEY")
	if zeptoKey == "" {
		log.Fatal("ZEPTO_API_KEY is not set")
	}
	fromEmail := os.Getenv("FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "noreply@smart-forms.in"
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cfg := auth.DefaultConfig(jwtSecret)
	var store auth.Store = postgres.New(pool, cfg)
	var mailer auth.Mailer = zeptomail.New(zeptoKey, fromEmail)

	// 1. Create schema
	if err := store.CreateSchema(ctx); err != nil {
		log.Fatalf("schema: %v", err)
	}
	fmt.Println("schema created")

	// 2. Create OTP
	email := "test@example.com"
	otp, err := store.CreateOTP(ctx, email)
	if err != nil {
		log.Fatalf("create otp: %v", err)
	}
	fmt.Printf("OTP created: %s (expires: %s)\n", otp.Code, otp.ExpiresAt)

	// 3. Send OTP email
	if err := mailer.SendOTP(ctx, email, otp.Code, cfg.OTPExpiry); err != nil {
		log.Fatalf("send otp: %v", err)
	}
	fmt.Println("OTP email sent")

	// 4. Verify OTP (auto-creates user)
	user, err := store.VerifyOTP(ctx, email, otp.Code)
	if err != nil {
		log.Fatalf("verify otp: %v", err)
	}
	fmt.Printf("User verified: %s (%s)\n", user.ID, user.Email)

	// 5. Generate tokens
	tokens, err := auth.GenerateTokenPair(cfg, user)
	if err != nil {
		log.Fatalf("generate tokens: %v", err)
	}
	fmt.Printf("Access token:  %s...\n", tokens.AccessToken[:50])
	fmt.Printf("Refresh token: %s...\n", tokens.RefreshToken[:50])

	// 6. Validate access token
	claims, err := auth.ValidateToken(cfg, tokens.AccessToken)
	if err != nil {
		log.Fatalf("validate token: %v", err)
	}
	fmt.Printf("Token claims: user_id=%s, email=%s, type=%s\n", claims.UserID, claims.Email, claims.Type)

	// 7. Look up user by ID
	found, err := store.GetUserByID(ctx, user.ID)
	if err != nil {
		log.Fatalf("get user: %v", err)
	}
	fmt.Printf("Found user: %s (%s)\n", found.ID, found.Email)

	fmt.Println("\nAll operations completed successfully!")
}
