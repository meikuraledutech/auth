package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/meikuraledutech/auth/v2"
)

// CreateOrganizationWithPermissions creates a new organization with assigned permissions.
// Idempotent — returns existing organization if already exists.
func (s *PGStore) CreateOrganizationWithPermissions(ctx context.Context, name string, permissionKeys []string) (*auth.Organization, error) {
	// Check if already exists
	existing, err := s.GetOrganizationByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}

	org := &auth.Organization{
		ID:   uuid.NewString(),
		Name: name,
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO auth_organizations (id, name) VALUES ($1, $2)`,
		org.ID, org.Name,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: create organization: %w", err)
	}

	// Assign permissions
	if len(permissionKeys) > 0 {
		if err := s.AssignPermissionsToOrganization(ctx, org.ID, permissionKeys); err != nil {
			return nil, err
		}
	}

	return org, nil
}

// GetOrganization fetches an organization by ID, including its permissions.
func (s *PGStore) GetOrganization(ctx context.Context, id string) (*auth.Organization, error) {
	var org auth.Organization
	err := s.db.QueryRow(ctx,
		`SELECT id, name, created_at FROM auth_organizations WHERE id = $1`, id,
	).Scan(&org.ID, &org.Name, &org.CreatedAt)

	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: get organization: %w", err)
	}

	// Fetch organization's permissions
	perms, err := s.GetOrganizationPermissions(ctx, id)
	if err != nil {
		return nil, err
	}
	org.Permissions = perms

	return &org, nil
}

// GetOrganizationByName fetches an organization by name.
func (s *PGStore) GetOrganizationByName(ctx context.Context, name string) (*auth.Organization, error) {
	var org auth.Organization
	err := s.db.QueryRow(ctx,
		`SELECT id, name, created_at FROM auth_organizations WHERE name = $1`, name,
	).Scan(&org.ID, &org.Name, &org.CreatedAt)

	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: get organization by name: %w", err)
	}

	// Fetch organization's permissions
	perms, err := s.GetOrganizationPermissions(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	org.Permissions = perms

	return &org, nil
}

// ListOrganizations returns all organizations (without permissions).
func (s *PGStore) ListOrganizations(ctx context.Context) ([]auth.Organization, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, created_at FROM auth_organizations ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("auth: list organizations: %w", err)
	}
	defer rows.Close()

	orgs := []auth.Organization{}
	for rows.Next() {
		var org auth.Organization
		if err := rows.Scan(&org.ID, &org.Name, &org.CreatedAt); err != nil {
			return nil, fmt.Errorf("auth: scan organization: %w", err)
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}

// GetOrganizationPermissions returns all permissions for an organization.
func (s *PGStore) GetOrganizationPermissions(ctx context.Context, orgID string) ([]auth.Permission, error) {
	rows, err := s.db.Query(ctx,
		`SELECT p.id, p.key, p.description, p.created_at
		 FROM auth_permissions p
		 JOIN auth_organization_permissions op ON op.permission_id = p.id
		 WHERE op.organization_id = $1
		 ORDER BY p.key`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: get organization permissions: %w", err)
	}
	defer rows.Close()

	perms := []auth.Permission{}
	for rows.Next() {
		var p auth.Permission
		if err := rows.Scan(&p.ID, &p.Key, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("auth: scan permission: %w", err)
		}
		perms = append(perms, p)
	}

	return perms, rows.Err()
}

// AssignPermissionsToOrganization assigns permissions to an organization.
func (s *PGStore) AssignPermissionsToOrganization(ctx context.Context, orgID string, permissionKeys []string) error {
	for _, key := range permissionKeys {
		p, err := s.GetPermission(ctx, key)
		if err != nil {
			return err
		}
		if p == nil {
			return auth.ErrPermissionNotFound
		}

		_, err = s.db.Exec(ctx,
			`INSERT INTO auth_organization_permissions (organization_id, permission_id)
			 VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			orgID, p.ID,
		)
		if err != nil {
			return fmt.Errorf("auth: assign permission to organization: %w", err)
		}
	}
	return nil
}

// RemovePermissionsFromOrganization removes permissions from an organization.
func (s *PGStore) RemovePermissionsFromOrganization(ctx context.Context, orgID string, permissionKeys []string) error {
	for _, key := range permissionKeys {
		p, err := s.GetPermission(ctx, key)
		if err != nil {
			return err
		}
		if p == nil {
			return auth.ErrPermissionNotFound
		}

		_, err = s.db.Exec(ctx,
			`DELETE FROM auth_organization_permissions
			 WHERE organization_id = $1 AND permission_id = $2`,
			orgID, p.ID,
		)
		if err != nil {
			return fmt.Errorf("auth: remove permission from organization: %w", err)
		}
	}
	return nil
}

// AddUsersToGroup adds multiple users to a group in bulk.
func (s *PGStore) AddUsersToGroup(ctx context.Context, groupID string, userIDs []string) error {
	if len(userIDs) == 0 {
		return nil
	}

	_, err := s.db.Exec(ctx,
		`INSERT INTO auth_user_groups (user_id, group_id)
		 SELECT unnest($1::TEXT[]), $2
		 ON CONFLICT DO NOTHING`,
		userIDs, groupID,
	)
	if err != nil {
		return fmt.Errorf("auth: add users to group: %w", err)
	}
	return nil
}

// RemoveUsersFromGroup removes multiple users from a group in bulk.
func (s *PGStore) RemoveUsersFromGroup(ctx context.Context, groupID string, userIDs []string) error {
	if len(userIDs) == 0 {
		return nil
	}

	_, err := s.db.Exec(ctx,
		`DELETE FROM auth_user_groups
		 WHERE group_id = $1 AND user_id = ANY($2::TEXT[])`,
		groupID, userIDs,
	)
	if err != nil {
		return fmt.Errorf("auth: remove users from group: %w", err)
	}
	return nil
}

// GetGroupMembers returns all users in a group.
func (s *PGStore) GetGroupMembers(ctx context.Context, groupID string) ([]auth.User, error) {
	rows, err := s.db.Query(ctx,
		`SELECT u.id, u.email, u.organization, u.created_at
		 FROM auth_users u
		 JOIN auth_user_groups ug ON ug.user_id = u.id
		 WHERE ug.group_id = $1
		 ORDER BY u.email`, groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: get group members: %w", err)
	}
	defer rows.Close()

	users := []auth.User{}
	for rows.Next() {
		var u auth.User
		var org *string
		if err := rows.Scan(&u.ID, &u.Email, &org, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("auth: scan user: %w", err)
		}
		if org != nil {
			u.Organization = *org
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// GetAllUserPermissions returns all permissions for a user (direct + from groups + from organizations).
func (s *PGStore) GetAllUserPermissions(ctx context.Context, userID string) ([]auth.Permission, error) {
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT p.id, p.key, p.description, p.created_at
		 FROM auth_permissions p
		 WHERE p.id IN (
			 SELECT permission_id FROM auth_user_permissions WHERE user_id = $1
			 UNION
			 SELECT gp.permission_id FROM auth_group_permissions gp
			 JOIN auth_user_groups ug ON ug.group_id = gp.group_id
			 WHERE ug.user_id = $1
			 UNION
			 SELECT op.permission_id FROM auth_organization_permissions op
			 JOIN auth_organizations o ON o.id = op.organization_id
			 JOIN auth_users u ON u.organization = o.name
			 WHERE u.id = $1
		 )
		 ORDER BY p.key`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: get all user permissions: %w", err)
	}
	defer rows.Close()

	perms := []auth.Permission{}
	for rows.Next() {
		var p auth.Permission
		if err := rows.Scan(&p.ID, &p.Key, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("auth: scan permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// HasAnyPermission checks if a user has any of the given permissions.
func (s *PGStore) HasAnyPermission(ctx context.Context, userID string, permissionKeys []string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM auth_permissions p
			WHERE p.key = ANY($2::TEXT[])
			AND p.id IN (
				SELECT permission_id FROM auth_user_permissions WHERE user_id = $1
				UNION
				SELECT gp.permission_id FROM auth_group_permissions gp
				JOIN auth_user_groups ug ON ug.group_id = gp.group_id
				WHERE ug.user_id = $1
				UNION
				SELECT op.permission_id FROM auth_organization_permissions op
				JOIN auth_organizations o ON o.id = op.organization_id
				JOIN auth_users u ON u.organization = o.name
				WHERE u.id = $1
			)
		)`, userID, permissionKeys,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("auth: has any permission: %w", err)
	}
	return exists, nil
}
