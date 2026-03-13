package postgres

import (
	"context"
	"fmt"
	"log"

	"github.com/meikuraledutech/auth/v2"
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
// organizations is optional variadic map of organization name -> permission keys.
func (s *PGStore) Bootstrap(ctx context.Context, superAdminEmail string, organizations ...map[string][]string) error {
	// 1. Run migrations if AutoMigrate is enabled.
	if s.cfg.AutoMigrate {
		if err := s.Migrate(ctx); err != nil {
			return fmt.Errorf("auth: bootstrap migrate: %w", err)
		}
		log.Println("auth: migrations applied")
	} else {
		// If not auto-migrating, caller must have called Migrate() already.
		// But we still ensure the migrations table exists so subsequent code works.
		if err := s.ensureMigrationsTable(ctx); err != nil {
			return fmt.Errorf("auth: bootstrap ensure migrations table: %w", err)
		}
	}

	// 2. Seed default permissions.
	for _, dp := range defaultPermissions {
		if _, err := s.CreatePermission(ctx, dp.Key, dp.Description); err != nil {
			return fmt.Errorf("auth: bootstrap permission %s: %w", dp.Key, err)
		}
	}
	log.Println("auth: default permissions seeded")

	// 2b. Create additional permissions needed by organizations.
	if len(organizations) > 0 {
		permissionKeysNeeded := make(map[string]bool)
		for _, permKeys := range organizations[0] {
			for _, key := range permKeys {
				permissionKeysNeeded[key] = true
			}
		}
		for key := range permissionKeysNeeded {
			if _, err := s.CreatePermission(ctx, key, "Organization permission"); err != nil {
				return fmt.Errorf("auth: bootstrap permission %s: %w", key, err)
			}
		}
	}

	// 3. Seed organizations if provided.
	if len(organizations) > 0 {
		for orgName, permKeys := range organizations[0] {
			if _, err := s.CreateOrganizationWithPermissions(ctx, orgName, permKeys); err != nil {
				return fmt.Errorf("auth: bootstrap organization %s: %w", orgName, err)
			}
		}
		log.Println("auth: organizations seeded")
	}

	// 4. Ensure super admin user exists.
	// Assign to "super_admin" organization if it exists, otherwise create without org.
	var user *auth.User
	var err error
	if len(organizations) > 0 {
		orgMap := organizations[0]
		if _, ok := orgMap["super_admin"]; ok {
			user, err = s.CreateUserWithOrganization(ctx, superAdminEmail, "super_admin")
		} else {
			user, err = s.CreateUser(ctx, superAdminEmail)
		}
	} else {
		user, err = s.CreateUser(ctx, superAdminEmail)
	}
	if err != nil {
		return fmt.Errorf("auth: bootstrap super admin: %w", err)
	}

	// 5. Assign all permissions to super admin.
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
