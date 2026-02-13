package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meikuraledutech/auth"
	"github.com/meikuraledutech/auth/postgres"
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

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cfg := auth.DefaultConfig(jwtSecret, "admin@example.com")
	var store auth.Store = postgres.New(pool, cfg)

	// 1. Bootstrap (schema + default permissions + super admin)
	if err := store.Bootstrap(ctx, "admin@example.com"); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	// 2. Create app-specific permissions
	store.CreatePermission(ctx, "forms:create", "Can create forms")
	store.CreatePermission(ctx, "forms:read", "Can view forms")
	store.CreatePermission(ctx, "forms:delete", "Can delete forms")

	// 3. Create a group
	group, err := store.CreateGroup(ctx, "Editor")
	if err != nil {
		log.Fatalf("create group: %v", err)
	}
	store.AddPermissionToGroup(ctx, group.ID, "forms:create")
	store.AddPermissionToGroup(ctx, group.ID, "forms:read")
	fmt.Printf("Group created: %s (%s)\n", group.Name, group.ID)

	// 4. Create OTP and verify (simulates login)
	otp, _ := store.CreateOTP(ctx, "user@example.com")
	user, _ := store.VerifyOTP(ctx, "user@example.com", otp.Code)
	fmt.Printf("User: %s (%s)\n", user.Email, user.ID)

	// 5. Assign user to group
	store.AssignUserToGroup(ctx, user.ID, group.ID)

	// 6. Also give a direct permission
	store.AssignPermission(ctx, user.ID, "forms:delete")

	// 7. Check resolved permissions (group + direct)
	perms, _ := store.GetResolvedPermissions(ctx, user.ID)
	fmt.Printf("Resolved permissions (%d):\n", len(perms))
	for _, p := range perms {
		fmt.Printf("  - %s\n", p.Key)
	}

	// 8. Check specific permission
	has, _ := store.HasResolvedPermission(ctx, user.ID, "forms:create")
	fmt.Printf("Has forms:create? %v\n", has)

	has, _ = store.HasResolvedPermission(ctx, user.ID, "billing:manage")
	fmt.Printf("Has billing:manage? %v\n", has)

	// 9. Generate tokens with permissions and groups
	permKeys := make([]string, len(perms))
	for i, p := range perms {
		permKeys[i] = p.Key
	}

	userGroups, _ := store.GetUserGroups(ctx, user.ID)
	groupNames := make([]string, len(userGroups))
	for i, g := range userGroups {
		groupNames[i] = g.Name
	}

	tokens, _ := auth.GenerateTokenPair(cfg, user, permKeys, groupNames)
	fmt.Printf("Access token: %s...\n", tokens.AccessToken[:50])

	// 10. Validate and check permissions and groups from token
	claims, _ := auth.ValidateToken(cfg, tokens.AccessToken)
	fmt.Printf("Permissions in token (%d):\n", len(claims.Permissions))
	for _, p := range claims.Permissions {
		fmt.Printf("  - %s\n", p)
	}
	fmt.Printf("Groups in token (%d):\n", len(claims.Groups))
	for _, g := range claims.Groups {
		fmt.Printf("  - %s\n", g)
	}

	fmt.Println("\nAll operations completed!")
}
