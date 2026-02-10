package postgres

import (
	"context"
	"fmt"
	"log"
)

// Default permissions seeded on bootstrap.
var defaultPermissions = []struct {
	Key         string
	Description string
}{
	{"permissions:manage", "Create, list, and delete permissions"},
	{"groups:manage", "Create, delete groups and manage their permissions"},
	{"users:manage", "List users, assign permissions and groups to users"},
}

// Bootstrap creates the schema, seeds default permissions, and ensures the super admin
// user exists with all permissions. Safe to call on every server start (idempotent).
func (s *PGStore) Bootstrap(ctx context.Context, superAdminEmail string) error {
	// 1. Create schema.
	if err := s.CreateSchema(ctx); err != nil {
		return fmt.Errorf("auth: bootstrap schema: %w", err)
	}
	log.Println("auth: schema ready")

	// 2. Seed default permissions.
	for _, dp := range defaultPermissions {
		if _, err := s.CreatePermission(ctx, dp.Key, dp.Description); err != nil {
			return fmt.Errorf("auth: bootstrap permission %s: %w", dp.Key, err)
		}
	}
	log.Println("auth: default permissions seeded")

	// 3. Ensure super admin user exists.
	user, err := s.CreateUser(ctx, superAdminEmail)
	if err != nil {
		return fmt.Errorf("auth: bootstrap super admin: %w", err)
	}

	// 4. Assign all permissions to super admin.
	allPerms, err := s.ListPermissions(ctx)
	if err != nil {
		return fmt.Errorf("auth: bootstrap list permissions: %w", err)
	}
	for _, p := range allPerms {
		if err := s.AssignPermission(ctx, user.ID, p.Key); err != nil {
			return fmt.Errorf("auth: bootstrap assign %s: %w", p.Key, err)
		}
	}
	log.Printf("auth: super admin ready (%s)\n", superAdminEmail)

	return nil
}
