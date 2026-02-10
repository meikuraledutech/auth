package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/meikuraledutech/auth"
)

// CreatePermission creates a new permission with the given key and description.
func (s *PGStore) CreatePermission(ctx context.Context, key string, description string) (*auth.Permission, error) {
	// Check if already exists.
	existing, err := s.GetPermission(ctx, key)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}

	p := &auth.Permission{
		ID:          uuid.NewString(),
		Key:         key,
		Description: description,
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO auth_permissions (id, key, description) VALUES ($1, $2, $3)`,
		p.ID, p.Key, p.Description,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: create permission: %w", err)
	}
	return p, nil
}

// GetPermission fetches a permission by its key.
func (s *PGStore) GetPermission(ctx context.Context, key string) (*auth.Permission, error) {
	var p auth.Permission
	err := s.db.QueryRow(ctx,
		`SELECT id, key, description, created_at FROM auth_permissions WHERE key = $1`, key,
	).Scan(&p.ID, &p.Key, &p.Description, &p.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: get permission: %w", err)
	}
	return &p, nil
}

// ListPermissions returns all permissions.
func (s *PGStore) ListPermissions(ctx context.Context) ([]auth.Permission, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, key, description, created_at FROM auth_permissions ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("auth: list permissions: %w", err)
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

// DeletePermission deletes a permission by its ID. Cascades to user_permissions and group_permissions.
func (s *PGStore) DeletePermission(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM auth_permissions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("auth: delete permission: %w", err)
	}
	return nil
}

// AssignPermission assigns a permission directly to a user.
func (s *PGStore) AssignPermission(ctx context.Context, userID string, permissionKey string) error {
	p, err := s.GetPermission(ctx, permissionKey)
	if err != nil {
		return err
	}
	if p == nil {
		return auth.ErrPermissionNotFound
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO auth_user_permissions (user_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		userID, p.ID,
	)
	if err != nil {
		return fmt.Errorf("auth: assign permission: %w", err)
	}
	return nil
}

// RevokePermission removes a direct permission from a user.
func (s *PGStore) RevokePermission(ctx context.Context, userID string, permissionKey string) error {
	p, err := s.GetPermission(ctx, permissionKey)
	if err != nil {
		return err
	}
	if p == nil {
		return auth.ErrPermissionNotFound
	}

	_, err = s.db.Exec(ctx,
		`DELETE FROM auth_user_permissions WHERE user_id = $1 AND permission_id = $2`,
		userID, p.ID,
	)
	if err != nil {
		return fmt.Errorf("auth: revoke permission: %w", err)
	}
	return nil
}

// GetUserPermissions returns all direct permissions for a user.
func (s *PGStore) GetUserPermissions(ctx context.Context, userID string) ([]auth.Permission, error) {
	rows, err := s.db.Query(ctx,
		`SELECT p.id, p.key, p.description, p.created_at
		 FROM auth_permissions p
		 JOIN auth_user_permissions up ON up.permission_id = p.id
		 WHERE up.user_id = $1
		 ORDER BY p.key`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: get user permissions: %w", err)
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

// HasPermission checks if a user has a specific direct permission.
func (s *PGStore) HasPermission(ctx context.Context, userID string, permissionKey string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM auth_user_permissions up
			JOIN auth_permissions p ON p.id = up.permission_id
			WHERE up.user_id = $1 AND p.key = $2
		)`, userID, permissionKey,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("auth: has permission: %w", err)
	}
	return exists, nil
}

// GetResolvedPermissions returns all permissions for a user (direct + from groups), deduplicated.
func (s *PGStore) GetResolvedPermissions(ctx context.Context, userID string) ([]auth.Permission, error) {
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT p.id, p.key, p.description, p.created_at
		 FROM auth_permissions p
		 WHERE p.id IN (
			 SELECT permission_id FROM auth_user_permissions WHERE user_id = $1
			 UNION
			 SELECT gp.permission_id FROM auth_group_permissions gp
			 JOIN auth_user_groups ug ON ug.group_id = gp.group_id
			 WHERE ug.user_id = $1
		 )
		 ORDER BY p.key`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: get resolved permissions: %w", err)
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

// HasResolvedPermission checks if a user has a permission (direct or via group).
func (s *PGStore) HasResolvedPermission(ctx context.Context, userID string, permissionKey string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM auth_permissions p
			WHERE p.key = $2 AND p.id IN (
				SELECT permission_id FROM auth_user_permissions WHERE user_id = $1
				UNION
				SELECT gp.permission_id FROM auth_group_permissions gp
				JOIN auth_user_groups ug ON ug.group_id = gp.group_id
				WHERE ug.user_id = $1
			)
		)`, userID, permissionKey,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("auth: has resolved permission: %w", err)
	}
	return exists, nil
}
