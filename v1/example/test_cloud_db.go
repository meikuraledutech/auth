package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meikuraledutech/auth/v1"
	"github.com/meikuraledutech/auth/v1/postgres"
)

func testCloudDB() {
	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "test-secret-key-for-testing"
		log.Println("⚠ Using default JWT_SECRET for testing")
	}

	// Connect to database
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer pool.Close()

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	fmt.Println("✓ Connected to Neon cloud database")

	// Create store with AutoMigrate enabled
	cfg := auth.DefaultConfig(jwtSecret, "admin@example.com")
	cfg.AutoMigrate = true
	store := postgres.New(pool, cfg)

	// Test 1: Run migrations
	fmt.Println("\n=== Running Migrations ===")
	if err := store.Migrate(ctx); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	fmt.Println("✓ Migrations applied successfully")

	// Test 2: Check migration status
	fmt.Println("\n=== Migration Status ===")
	migrations, err := store.MigrationStatus(ctx)
	if err != nil {
		log.Fatalf("Failed to get migration status: %v", err)
	}

	for _, m := range migrations {
		status := "⏳ pending"
		if m.Applied {
			status = "✓ applied"
		}
		fmt.Printf("  %s: %s\n", m.Name, status)
	}

	// Test 3: Verify tables exist
	fmt.Println("\n=== Verifying Database Schema ===")
	var tableCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name LIKE 'auth_%'
	`).Scan(&tableCount); err != nil {
		log.Fatalf("Failed to count tables: %v", err)
	}
	fmt.Printf("✓ Auth tables in database: %d\n", tableCount)

	// Test 4: Check existing data
	fmt.Println("\n=== Existing Data ===")
	var userCount, permCount, groupCount int
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM auth_users").Scan(&userCount)
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM auth_permissions").Scan(&permCount)
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM auth_groups").Scan(&groupCount)

	fmt.Printf("  Users: %d\n", userCount)
	fmt.Printf("  Permissions: %d\n", permCount)
	fmt.Printf("  Groups: %d\n", groupCount)

	fmt.Println("\n✓ All migration tests passed!")
}
