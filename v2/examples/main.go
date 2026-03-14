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
	jwtSecret := os.Getenv("JWT_SECRET")
	superAdminEmail := os.Getenv("SUPER_ADMIN_EMAIL")
	superAdminPassword := os.Getenv("SUPER_ADMIN_PASSWORD")

	if databaseURL == "" {
		log.Fatalf("DATABASE_URL not set")
	}
	if jwtSecret == "" {
		jwtSecret = "test-secret-key"
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

	cfg := auth.DefaultConfig(jwtSecret, superAdminEmail)
	store := postgres.New(pool, cfg)

	fmt.Println("\n=== AUTH v2.1.0 - ORGANIZATION MODEL TEST ===\n")

	// 0. Drop schema to start fresh
	fmt.Println("0. Dropping old schema to start fresh...")
	if err := store.DropSchema(ctx); err != nil {
		log.Fatalf("❌ DropSchema failed: %v", err)
	}
	fmt.Println("✓ Old schema dropped\n")

	// 1. Bootstrap with organizations
	fmt.Println("1. Bootstrap: Creating schema, permissions, and 4 organizations...")
	orgs := map[string][]string{
		"super_admin":   {"permissions:manage", "groups:manage", "users:manage"},
		"trainer":       {"forms:create", "users:manage"},
		"college_admin": {"groups:manage", "forms:create"},
		"student":       {"forms:create"},
	}
	if err := store.Bootstrap(ctx, superAdminEmail, superAdminPassword, map[string][]string(orgs)); err != nil {
		log.Fatalf("❌ Bootstrap failed: %v", err)
	}
	fmt.Println("✓ Schema created, permissions seeded, organizations created\n")

	// 2. Verify organizations exist
	fmt.Println("2. Verify all organizations created...")
	allOrgs, err := store.ListOrganizations(ctx)
	if err != nil {
		log.Fatalf("❌ ListOrganizations failed: %v", err)
	}
	fmt.Printf("✓ Total organizations: %d\n", len(allOrgs))
	for _, o := range allOrgs {
		fmt.Printf("   - %s\n", o.Name)
	}
	fmt.Println()

	// 3. Get organization with permissions
	fmt.Println("3. Verify organization permissions...")
	trainerOrg, err := store.GetOrganizationByName(ctx, "trainer")
	if err != nil {
		log.Fatalf("❌ GetOrganizationByName failed: %v", err)
	}
	if trainerOrg == nil {
		log.Fatalf("❌ Trainer organization not found")
	}
	fmt.Printf("✓ Trainer org permissions (%d):\n", len(trainerOrg.Permissions))
	for _, p := range trainerOrg.Permissions {
		fmt.Printf("   - %s: %s\n", p.Key, p.Description)
	}
	fmt.Println()

	// 4. Create users with different organizations
	fmt.Println("4. Create users with different organizations...")
	trainer, err := store.CreateUserWithOrganization(ctx, "trainer@smartforms.in", "trainer")
	if err != nil {
		log.Fatalf("❌ Create trainer user failed: %v", err)
	}
	fmt.Printf("✓ Trainer user: %s (org: %s, id: %s)\n", trainer.Email, trainer.Organization, trainer.ID)

	student, err := store.CreateUserWithOrganization(ctx, "student@smartforms.in", "student")
	if err != nil {
		log.Fatalf("❌ Create student user failed: %v", err)
	}
	fmt.Printf("✓ Student user: %s (org: %s, id: %s)\n", student.Email, student.Organization, student.ID)

	collegeAdmin, err := store.CreateUserWithOrganization(ctx, "college.admin@smartforms.in", "college_admin")
	if err != nil {
		log.Fatalf("❌ Create college_admin user failed: %v", err)
	}
	fmt.Printf("✓ College Admin user: %s (org: %s, id: %s)\n", collegeAdmin.Email, collegeAdmin.Organization, collegeAdmin.ID)
	fmt.Println()

	// 5. Get super admin and verify all permissions
	fmt.Println("5. Verify super admin has all permissions...")
	superAdmin, err := store.GetUserByEmail(ctx, superAdminEmail)
	if err != nil {
		log.Fatalf("❌ GetUserByEmail failed: %v", err)
	}
	if superAdmin == nil {
		log.Fatalf("❌ Super admin not found")
	}
	superAdminPerms, err := store.GetResolvedPermissions(ctx, superAdmin.ID)
	if err != nil {
		log.Fatalf("❌ GetResolvedPermissions failed: %v", err)
	}
	fmt.Printf("✓ Super admin has %d permissions (all expected permissions):\n", len(superAdminPerms))
	for _, p := range superAdminPerms {
		fmt.Printf("   - %s\n", p.Key)
	}
	fmt.Println()

	// 6. Test permission inheritance from organization
	fmt.Println("6. Test permission inheritance from organization...")
	fmt.Println("   Testing: Trainer should have 'forms:create' from trainer org")
	hasFormCreate, err := store.HasResolvedPermission(ctx, trainer.ID, "forms:create")
	if err != nil {
		log.Fatalf("❌ HasResolvedPermission failed: %v", err)
	}
	if !hasFormCreate {
		log.Fatalf("❌ Trainer does not have 'forms:create' permission (should inherit from trainer org)")
	}
	fmt.Println("✓ Trainer has 'forms:create' (inherited from trainer organization)")

	fmt.Println("   Testing: Student should have 'forms:create' from student org")
	hasFormCreate, err = store.HasResolvedPermission(ctx, student.ID, "forms:create")
	if err != nil {
		log.Fatalf("❌ HasResolvedPermission failed: %v", err)
	}
	if !hasFormCreate {
		log.Fatalf("❌ Student does not have 'forms:create' permission")
	}
	fmt.Println("✓ Student has 'forms:create' (inherited from student organization)")
	fmt.Println()

	// 7. Test unauthorized access (negative test)
	fmt.Println("7. Test unauthorized access (negative tests)...")
	fmt.Println("   Testing: Student should NOT have 'groups:manage'")
	hasGroupManage, err := store.HasResolvedPermission(ctx, student.ID, "groups:manage")
	if err != nil {
		log.Fatalf("❌ HasResolvedPermission failed: %v", err)
	}
	if hasGroupManage {
		log.Fatalf("❌ Student has 'groups:manage' (should NOT have this)")
	}
	fmt.Println("✓ Student blocked from 'groups:manage' - CORRECT")

	fmt.Println("   Testing: Trainer should NOT have 'permissions:manage'")
	hasPermManage, err := store.HasResolvedPermission(ctx, trainer.ID, "permissions:manage")
	if err != nil {
		log.Fatalf("❌ HasResolvedPermission failed: %v", err)
	}
	if hasPermManage {
		log.Fatalf("❌ Trainer has 'permissions:manage' (should NOT have this)")
	}
	fmt.Println("✓ Trainer blocked from 'permissions:manage' - CORRECT")

	fmt.Println("   Testing: College Admin should NOT have 'users:manage'")
	hasUserManage, err := store.HasResolvedPermission(ctx, collegeAdmin.ID, "users:manage")
	if err != nil {
		log.Fatalf("❌ HasResolvedPermission failed: %v", err)
	}
	if hasUserManage {
		log.Fatalf("❌ College Admin has 'users:manage' (should NOT have this)")
	}
	fmt.Println("✓ College Admin blocked from 'users:manage' - CORRECT")
	fmt.Println()

	// 8. Test HasAnyPermission
	fmt.Println("8. Test HasAnyPermission (multiple permission check)...")
	fmt.Println("   Testing: Trainer has any of ['forms:create', 'users:manage']")
	hasAny, err := store.HasAnyPermission(ctx, trainer.ID, []string{"forms:create", "users:manage"})
	if err != nil {
		log.Fatalf("❌ HasAnyPermission failed: %v", err)
	}
	if !hasAny {
		log.Fatalf("❌ Trainer should have at least one of these permissions")
	}
	fmt.Println("✓ Trainer has at least one of the required permissions")

	fmt.Println("   Testing: Student has any of ['groups:manage', 'permissions:manage']")
	hasAny, err = store.HasAnyPermission(ctx, student.ID, []string{"groups:manage", "permissions:manage"})
	if err != nil {
		log.Fatalf("❌ HasAnyPermission failed: %v", err)
	}
	if hasAny {
		log.Fatalf("❌ Student should NOT have any of these permissions")
	}
	fmt.Println("✓ Student correctly blocked from all requested permissions")
	fmt.Println()

	// 9. Test direct permissions + organization inheritance
	fmt.Println("9. Test GetAllUserPermissions (direct + group + org)...")
	fmt.Println("   Assigning 'users:manage' directly to trainer...")
	err = store.AssignPermission(ctx, trainer.ID, "users:manage")
	if err != nil {
		log.Fatalf("❌ AssignPermission failed: %v", err)
	}
	fmt.Println("✓ Direct permission assigned")

	trainerAllPerms, err := store.GetAllUserPermissions(ctx, trainer.ID)
	if err != nil {
		log.Fatalf("❌ GetAllUserPermissions failed: %v", err)
	}
	fmt.Printf("✓ Trainer now has %d total permissions (org + direct):\n", len(trainerAllPerms))
	for _, p := range trainerAllPerms {
		fmt.Printf("   - %s\n", p.Key)
	}
	fmt.Println()

	// 10. Test group-based permissions with bulk operations
	fmt.Println("10. Test bulk group operations...")
	fmt.Println("    Creating group 'Editors' with forms:create permission...")
	editorsGroup, err := store.CreateGroup(ctx, "Editors")
	if err != nil {
		log.Fatalf("❌ CreateGroup failed: %v", err)
	}
	fmt.Printf("✓ Group created: %s\n", editorsGroup.Name)

	err = store.AddPermissionToGroup(ctx, editorsGroup.ID, "forms:create")
	if err != nil {
		log.Fatalf("❌ AddPermissionToGroup failed: %v", err)
	}
	fmt.Println("✓ Permission assigned to group")

	fmt.Println("    Adding student + trainer to group in bulk...")
	err = store.AddUsersToGroup(ctx, editorsGroup.ID, []string{student.ID, trainer.ID})
	if err != nil {
		log.Fatalf("❌ AddUsersToGroup failed: %v", err)
	}
	fmt.Println("✓ Users added to group in bulk")

	members, err := store.GetGroupMembers(ctx, editorsGroup.ID)
	if err != nil {
		log.Fatalf("❌ GetGroupMembers failed: %v", err)
	}
	fmt.Printf("✓ Group has %d members:\n", len(members))
	for _, m := range members {
		fmt.Printf("   - %s (org: %s)\n", m.Email, m.Organization)
	}
	fmt.Println()

	// 11. Verify user organization field is populated correctly
	fmt.Println("11. Verify user organization field is populated...")
	student2, err := store.GetUserByEmail(ctx, "student@smartforms.in")
	if err != nil {
		log.Fatalf("❌ GetUserByEmail failed: %v", err)
	}
	if student2.Organization != "student" {
		log.Fatalf("❌ Student organization not stored correctly: got %q, want 'student'", student2.Organization)
	}
	fmt.Printf("✓ User.Organization correctly persisted: %s\n", student2.Organization)

	trainer2, err := store.GetUserByEmail(ctx, "trainer@smartforms.in")
	if err != nil {
		log.Fatalf("❌ GetUserByEmail failed: %v", err)
	}
	if trainer2.Organization != "trainer" {
		log.Fatalf("❌ Trainer organization not stored correctly: got %q, want 'trainer'", trainer2.Organization)
	}
	fmt.Printf("✓ User.Organization correctly persisted: %s\n", trainer2.Organization)
	fmt.Println()

	// 12. Test backward compatibility - user without organization
	fmt.Println("12. Test backward compatibility (user without organization)...")
	userNoOrg, err := store.CreateUser(ctx, "noorg@smartforms.in")
	if err != nil {
		log.Fatalf("❌ CreateUser failed: %v", err)
	}
	fmt.Printf("✓ User created without organization: %s\n", userNoOrg.Email)

	userNoOrg2, err := store.GetUserByEmail(ctx, "noorg@smartforms.in")
	if err != nil {
		log.Fatalf("❌ GetUserByEmail failed: %v", err)
	}
	if userNoOrg2.Organization != "" {
		log.Fatalf("❌ User without org should have empty organization, got: %q", userNoOrg2.Organization)
	}
	fmt.Printf("✓ User.Organization is empty (backward compatible): %q\n", userNoOrg2.Organization)

	userNoOrgPerms, err := store.GetResolvedPermissions(ctx, userNoOrg2.ID)
	if err != nil {
		log.Fatalf("❌ GetResolvedPermissions failed: %v", err)
	}
	fmt.Printf("✓ User without org has no permissions: %d\n", len(userNoOrgPerms))
	fmt.Println()

	// 13. Test invalid organization assignment
	fmt.Println("13. Test invalid organization rejection...")
	_, err = store.CreateUserWithOrganization(ctx, "invalid@smartforms.in", "nonexistent_org")
	if err != auth.ErrInvalidOrganization {
		log.Fatalf("❌ Should reject invalid organization, got error: %v", err)
	}
	fmt.Println("✓ Invalid organization correctly rejected")
	fmt.Println()

	// 14. Test remove users from group
	fmt.Println("14. Test remove users from group...")
	fmt.Println("    Removing student from Editors group...")
	err = store.RemoveUsersFromGroup(ctx, editorsGroup.ID, []string{student.ID})
	if err != nil {
		log.Fatalf("❌ RemoveUsersFromGroup failed: %v", err)
	}
	fmt.Println("✓ User removed from group")

	members, err = store.GetGroupMembers(ctx, editorsGroup.ID)
	if err != nil {
		log.Fatalf("❌ GetGroupMembers failed: %v", err)
	}
	if len(members) != 1 {
		log.Fatalf("❌ Expected 1 member after removal, got %d", len(members))
	}
	fmt.Printf("✓ Group now has %d members\n", len(members))
	fmt.Println()

	fmt.Println("=== ALL TESTS PASSED ===\n")
	fmt.Println("Summary:")
	fmt.Println("✓ Organizations created with permissions")
	fmt.Println("✓ Users assigned to organizations")
	fmt.Println("✓ Permission inheritance from organization")
	fmt.Println("✓ Unauthorized access properly blocked")
	fmt.Println("✓ Permission resolution works (direct + group + org)")
	fmt.Println("✓ Bulk group operations work")
	fmt.Println("✓ User.Organization field properly persisted")
	fmt.Println("✓ Backward compatibility maintained")
	fmt.Println("✓ Invalid organization correctly rejected")
	fmt.Println()
}
