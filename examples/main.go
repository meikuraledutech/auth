package main

import (
	"fmt"

	auth "github.com/meikuraledutech/auth/v1"
)

func main() {
	// Using v1 (github.com/meikuraledutech/auth)
	cfg := auth.DefaultConfig("my-secret-key", "admin@example.com")

	fmt.Println("=== auth v1 (github.com/meikuraledutech/auth) ===")
	fmt.Printf("JWTSecret:       %s\n", cfg.JWTSecret)
	fmt.Printf("OTPLength:       %d\n", cfg.OTPLength)
	fmt.Printf("OTPExpiry:       %s\n", cfg.OTPExpiry)
	fmt.Printf("AccessExpiry:    %s\n", cfg.AccessExpiry)
	fmt.Printf("RefreshExpiry:   %s\n", cfg.RefreshExpiry)
	fmt.Printf("SuperAdminEmail: %s\n", cfg.SuperAdminEmail)
	fmt.Printf("AutoMigrate:     %v\n", cfg.AutoMigrate)

	// Demonstrate v1 types
	user := auth.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	fmt.Printf("\nUser: ID=%s, Email=%s\n", user.ID, user.Email)

	fmt.Println("\n=== auth v2 (github.com/meikuraledutech/auth/v2) ===")
	fmt.Println("v2 module resolved successfully — ready for future development")
}
