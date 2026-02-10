package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/meikuraledutech/auth"
)

// CreateGroup creates a new permission group.
func (s *PGStore) CreateGroup(ctx context.Context, name string) (*auth.Group, error) {
	g := &auth.Group{
		ID:   uuid.NewString(),
		Name: name,
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO auth_groups (id, name) VALUES ($1, $2)`,
		g.ID, g.Name,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: create group: %w", err)
	}
	return g, nil
}

// GetGroup fetches a group by ID, including its permissions.
func (s *PGStore) GetGroup(ctx context.Context, id string) (*auth.Group, error) {
	var g auth.Group
	err := s.db.QueryRow(ctx,
		`SELECT id, name, created_at FROM auth_groups WHERE id = $1`, id,
	).Scan(&g.ID, &g.Name, &g.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: get group: %w", err)
	}

	// Fetch group's permissions.
	rows, err := s.db.Query(ctx,
		`SELECT p.id, p.key, p.description, p.created_at
		 FROM auth_permissions p
		 JOIN auth_group_permissions gp ON gp.permission_id = p.id
		 WHERE gp.group_id = $1
		 ORDER BY p.key`, id,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: get group permissions: %w", err)
	}
	defer rows.Close()

	g.Permissions = []auth.Permission{}
	for rows.Next() {
		var p auth.Permission
		if err := rows.Scan(&p.ID, &p.Key, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("auth: scan permission: %w", err)
		}
		g.Permissions = append(g.Permissions, p)
	}

	return &g, rows.Err()
}

// ListGroups returns all groups (without permissions).
func (s *PGStore) ListGroups(ctx context.Context) ([]auth.Group, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, created_at FROM auth_groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("auth: list groups: %w", err)
	}
	defer rows.Close()

	groups := []auth.Group{}
	for rows.Next() {
		var g auth.Group
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("auth: scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// DeleteGroup deletes a group by ID. Cascades to group_permissions and user_groups.
func (s *PGStore) DeleteGroup(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM auth_groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("auth: delete group: %w", err)
	}
	return nil
}

// AddPermissionToGroup adds a permission to a group.
func (s *PGStore) AddPermissionToGroup(ctx context.Context, groupID string, permissionKey string) error {
	p, err := s.GetPermission(ctx, permissionKey)
	if err != nil {
		return err
	}
	if p == nil {
		return auth.ErrPermissionNotFound
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO auth_group_permissions (group_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		groupID, p.ID,
	)
	if err != nil {
		return fmt.Errorf("auth: add permission to group: %w", err)
	}
	return nil
}

// RemovePermissionFromGroup removes a permission from a group.
func (s *PGStore) RemovePermissionFromGroup(ctx context.Context, groupID string, permissionID string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM auth_group_permissions WHERE group_id = $1 AND permission_id = $2`,
		groupID, permissionID,
	)
	if err != nil {
		return fmt.Errorf("auth: remove permission from group: %w", err)
	}
	return nil
}

// AssignUserToGroup adds a user to a group.
func (s *PGStore) AssignUserToGroup(ctx context.Context, userID string, groupID string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO auth_user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		userID, groupID,
	)
	if err != nil {
		return fmt.Errorf("auth: assign user to group: %w", err)
	}
	return nil
}

// RemoveUserFromGroup removes a user from a group.
func (s *PGStore) RemoveUserFromGroup(ctx context.Context, userID string, groupID string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM auth_user_groups WHERE user_id = $1 AND group_id = $2`,
		userID, groupID,
	)
	if err != nil {
		return fmt.Errorf("auth: remove user from group: %w", err)
	}
	return nil
}

// GetUserGroups returns all groups a user belongs to.
func (s *PGStore) GetUserGroups(ctx context.Context, userID string) ([]auth.Group, error) {
	rows, err := s.db.Query(ctx,
		`SELECT g.id, g.name, g.created_at
		 FROM auth_groups g
		 JOIN auth_user_groups ug ON ug.group_id = g.id
		 WHERE ug.user_id = $1
		 ORDER BY g.name`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: get user groups: %w", err)
	}
	defer rows.Close()

	groups := []auth.Group{}
	for rows.Next() {
		var g auth.Group
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("auth: scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}
