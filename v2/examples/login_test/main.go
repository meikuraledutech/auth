package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	auth "github.com/meikuraledutech/auth/v2"
	"github.com/meikuraledutech/auth/v2/postgres"
)

func main() {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	superAdminEmail := os.Getenv("SUPER_ADMIN_EMAIL")
	superAdminPassword := os.Getenv("SUPER_ADMIN_PASSWORD")

	if databaseURL == "" {
		log.Fatalf("DATABASE_URL not set")
	}
	if superAdminEmail == "" {
		superAdminEmail = "admin@example.com"
	}
	if superAdminPassword == "" {
		superAdminPassword = "AdminPassword@123"
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	cfg := auth.DefaultConfig("test-secret", superAdminEmail)
	store := postgres.New(pool, cfg)

	fmt.Println("\n=== SUPER ADMIN PASSWORD LOGIN TEST ===\n")

	// 1. Try to login with super admin email and password
	fmt.Printf("Testing login: email=%s, password=%s\n\n", superAdminEmail, superAdminPassword)

	user, err := store.LoginWithPassword(ctx, superAdminEmail, superAdminPassword)
	if err != nil {
		fmt.Printf("❌ Login failed: %v\n", err)
		if err == auth.ErrPasswordNotSet {
			fmt.Println("   → Password was NOT set in the database")
		} else if err == auth.ErrPasswordInvalid {
			fmt.Println("   → Password is incorrect or user doesn't exist")
		}
		return
	}

	fmt.Printf("✓ Login successful!\n")
	fmt.Printf("  - User ID: %s\n", user.ID)
	fmt.Printf("  - Email: %s\n", user.Email)
	fmt.Printf("  - Organization: %s\n", user.Organization)
	fmt.Println()

	// 2. Verify user has permissions
	perms, err := store.GetResolvedPermissions(ctx, user.ID)
	if err != nil {
		log.Fatalf("❌ Failed to get permissions: %v", err)
	}
	fmt.Printf("✓ Super admin has %d permissions:\n", len(perms))
	for _, p := range perms {
		fmt.Printf("   - %s\n", p.Key)
	}
	fmt.Println()

	// 3. Try with wrong password
	fmt.Println("Testing login with WRONG password...")
	_, err = store.LoginWithPassword(ctx, superAdminEmail, "WrongPassword123")
	if err == auth.ErrPasswordInvalid {
		fmt.Println("✓ Correctly rejected wrong password")
	} else {
		fmt.Printf("❌ Unexpected error: %v\n", err)
	}
}
