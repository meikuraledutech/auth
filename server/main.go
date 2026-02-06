package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meikuraledutech/auth"
	"github.com/meikuraledutech/auth/postgres"
	"github.com/meikuraledutech/auth/zeptomail"
)

func main() {
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

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cfg := auth.DefaultConfig(jwtSecret)
	var store auth.Store = postgres.New(pool, cfg)
	var mailer auth.Mailer = zeptomail.New(zeptoKey, fromEmail)

	app := fiber.New()

	// -- Schema --
	app.Post("/schema", func(c fiber.Ctx) error {
		if err := store.CreateSchema(c.Context()); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"message": "schema created"})
	})

	// -- Request OTP --
	app.Post("/otp", func(c fiber.Ctx) error {
		var body struct {
			Email string `json:"email"`
		}
		if err := c.Bind().JSON(&body); err != nil || body.Email == "" {
			return c.Status(400).JSON(fiber.Map{"error": "email is required"})
		}

		otp, err := store.CreateOTP(c.Context(), body.Email)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		if err := mailer.SendOTP(c.Context(), body.Email, otp.Code, cfg.OTPExpiry); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "failed to send email: " + err.Error()})
		}

		return c.Status(201).JSON(fiber.Map{
			"message":    "otp sent to " + body.Email,
			"expires_at": otp.ExpiresAt,
		})
	})

	// -- Verify OTP --
	app.Post("/verify", func(c fiber.Ctx) error {
		var body struct {
			Email string `json:"email"`
			Code  string `json:"code"`
		}
		if err := c.Bind().JSON(&body); err != nil || body.Email == "" || body.Code == "" {
			return c.Status(400).JSON(fiber.Map{"error": "email and code are required"})
		}

		user, err := store.VerifyOTP(c.Context(), body.Email, body.Code)
		if errors.Is(err, auth.ErrOTPInvalid) {
			return c.Status(401).JSON(fiber.Map{"error": "invalid otp"})
		}
		if errors.Is(err, auth.ErrOTPExpired) {
			return c.Status(401).JSON(fiber.Map{"error": "otp expired"})
		}
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		tokens, err := auth.GenerateTokenPair(cfg, user)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"user":          user,
		})
	})

	// -- Refresh Token --
	app.Post("/refresh", func(c fiber.Ctx) error {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.Bind().JSON(&body); err != nil || body.RefreshToken == "" {
			return c.Status(400).JSON(fiber.Map{"error": "refresh_token is required"})
		}

		claims, err := auth.ValidateToken(cfg, body.RefreshToken)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "invalid refresh token"})
		}
		if claims.Type != "refresh" {
			return c.Status(401).JSON(fiber.Map{"error": "not a refresh token"})
		}

		user, err := store.GetUserByID(c.Context(), claims.UserID)
		if err != nil || user == nil {
			return c.Status(401).JSON(fiber.Map{"error": "user not found"})
		}

		tokens, err := auth.GenerateTokenPair(cfg, user)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
		})
	})

	// -- Get Current User --
	app.Get("/me", func(c fiber.Ctx) error {
		header := c.Get("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			return c.Status(401).JSON(fiber.Map{"error": "missing authorization header"})
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")

		claims, err := auth.ValidateToken(cfg, tokenStr)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "invalid token"})
		}
		if claims.Type != "access" {
			return c.Status(401).JSON(fiber.Map{"error": "not an access token"})
		}

		user, err := store.GetUserByID(c.Context(), claims.UserID)
		if err != nil || user == nil {
			return c.Status(404).JSON(fiber.Map{"error": "user not found"})
		}

		return c.JSON(user)
	})

	log.Fatal(app.Listen(":3000"))
}
