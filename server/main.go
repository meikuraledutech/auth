package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meikuraledutech/auth"
	"github.com/meikuraledutech/auth/postgres"
	"github.com/meikuraledutech/auth/zeptomail"
)

var (
	store  auth.Store
	mailer auth.Mailer
	cfg    auth.Config
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set")
	}
	zeptoKey := os.Getenv("ZEPTO_API_KEY")
	if zeptoKey == "" {
		log.Fatal("ZEPTO_API_KEY is not set")
	}
	superAdminEmail := os.Getenv("SUPER_ADMIN_EMAIL")
	if superAdminEmail == "" {
		log.Fatal("SUPER_ADMIN_EMAIL is not set")
	}
	fromEmail := os.Getenv("FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "noreply@smart-forms.in"
	}

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cfg = auth.DefaultConfig(jwtSecret, superAdminEmail)
	store = postgres.New(pool, cfg)
	mailer = zeptomail.New(zeptoKey, fromEmail)

	// Bootstrap: schema + default permissions + super admin.
	if err := store.Bootstrap(context.Background(), superAdminEmail); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	app := fiber.New()

	// ─── Auth ─────────────────────────────────────────────
	app.Post("/otp", handleRequestOTP)
	app.Post("/verify", handleVerifyOTP)
	app.Post("/refresh", handleRefresh)
	app.Get("/me", handleMe)
	app.Get("/me/permissions", handleMyPermissions)

	// ─── Permissions (requires permissions:manage) ────────
	app.Post("/permissions", requirePermission("permissions:manage", handleCreatePermission))
	app.Get("/permissions", requirePermission("permissions:manage", handleListPermissions))
	app.Delete("/permissions/:id", requirePermission("permissions:manage", handleDeletePermission))

	// ─── Groups (requires groups:manage) ──────────────────
	app.Post("/groups", requirePermission("groups:manage", handleCreateGroup))
	app.Get("/groups", requirePermission("groups:manage", handleListGroups))
	app.Get("/groups/:id", requirePermission("groups:manage", handleGetGroup))
	app.Delete("/groups/:id", requirePermission("groups:manage", handleDeleteGroup))
	app.Post("/groups/:id/permissions", requirePermission("groups:manage", handleAddPermissionToGroup))
	app.Delete("/groups/:id/permissions/:permId", requirePermission("groups:manage", handleRemovePermissionFromGroup))

	// ─── User Management (requires users:manage) ─────────
	app.Get("/users", requirePermission("users:manage", handleListUsers))
	app.Get("/users/:id", requirePermission("users:manage", handleGetUser))
	app.Post("/users/:id/permissions", requirePermission("users:manage", handleAssignPermission))
	app.Delete("/users/:id/permissions/:permKey", requirePermission("users:manage", handleRevokePermission))
	app.Post("/users/:id/groups", requirePermission("users:manage", handleAssignUserToGroup))
	app.Delete("/users/:id/groups/:groupId", requirePermission("users:manage", handleRemoveUserFromGroup))

	log.Fatal(app.Listen(":3000"))
}

// ─── Middleware ──────────────────────────────────────────────

// extractUser validates the Bearer token and returns claims.
func extractUser(c fiber.Ctx) (*auth.Claims, error) {
	header := c.Get("Authorization")
	if header == "" || !strings.HasPrefix(header, "Bearer ") {
		return nil, errors.New("missing authorization header")
	}
	claims, err := auth.ValidateToken(cfg, strings.TrimPrefix(header, "Bearer "))
	if err != nil {
		return nil, err
	}
	if claims.Type != "access" {
		return nil, errors.New("not an access token")
	}
	return claims, nil
}

// requirePermission wraps a handler with auth + permission check.
func requirePermission(permKey string, handler fiber.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		claims, err := extractUser(c)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": err.Error()})
		}

		has, err := store.HasResolvedPermission(c.Context(), claims.UserID, permKey)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		if !has {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden: requires " + permKey})
		}

		c.Locals("claims", claims)
		return handler(c)
	}
}

// ─── Auth Handlers ──────────────────────────────────────────

func handleRequestOTP(c fiber.Ctx) error {
	var body struct {
		Email string `json:"email"`
	}
	if err := c.Bind().JSON(&body); err != nil || body.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email is required"})
	}

	otp, err := store.CreateOTP(c.Context(), body.Email)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if err := mailer.SendOTP(c.Context(), body.Email, otp.Code, cfg.OTPExpiry); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to send email: " + err.Error()})
	}

	return c.Status(201).JSON(fiber.Map{
		"message":    "otp sent to " + body.Email,
		"expires_at": otp.ExpiresAt,
	})
}

func handleVerifyOTP(c fiber.Ctx) error {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := c.Bind().JSON(&body); err != nil || body.Email == "" || body.Code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email and code are required"})
	}

	user, err := store.VerifyOTP(c.Context(), body.Email, body.Code)
	if errors.Is(err, auth.ErrOTPInvalid) {
		return c.Status(401).JSON(fiber.Map{"error": "invalid otp"})
	}
	if errors.Is(err, auth.ErrOTPExpired) {
		return c.Status(401).JSON(fiber.Map{"error": "otp expired"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	tokens, err := auth.GenerateTokenPair(cfg, user)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"user":          user,
	})
}

func handleRefresh(c fiber.Ctx) error {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.Bind().JSON(&body); err != nil || body.RefreshToken == "" {
		return c.Status(400).JSON(fiber.Map{"error": "refresh_token is required"})
	}

	claims, err := auth.ValidateToken(cfg, body.RefreshToken)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "invalid refresh token"})
	}
	if claims.Type != "refresh" {
		return c.Status(401).JSON(fiber.Map{"error": "not a refresh token"})
	}

	user, err := store.GetUserByID(c.Context(), claims.UserID)
	if err != nil || user == nil {
		return c.Status(401).JSON(fiber.Map{"error": "user not found"})
	}

	tokens, err := auth.GenerateTokenPair(cfg, user)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func handleMe(c fiber.Ctx) error {
	claims, err := extractUser(c)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": err.Error()})
	}

	user, err := store.GetUserByID(c.Context(), claims.UserID)
	if err != nil || user == nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}

	return c.JSON(user)
}

func handleMyPermissions(c fiber.Ctx) error {
	claims, err := extractUser(c)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": err.Error()})
	}

	perms, err := store.GetResolvedPermissions(c.Context(), claims.UserID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(perms)
}

// ─── Permission Handlers ────────────────────────────────────

func handleCreatePermission(c fiber.Ctx) error {
	var body struct {
		Key         string `json:"key"`
		Description string `json:"description"`
	}
	if err := c.Bind().JSON(&body); err != nil || body.Key == "" {
		return c.Status(400).JSON(fiber.Map{"error": "key is required"})
	}

	perm, err := store.CreatePermission(c.Context(), body.Key, body.Description)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(perm)
}

func handleListPermissions(c fiber.Ctx) error {
	perms, err := store.ListPermissions(c.Context())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(perms)
}

func handleDeletePermission(c fiber.Ctx) error {
	if err := store.DeletePermission(c.Context(), c.Params("id")); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}

// ─── Group Handlers ─────────────────────────────────────────

func handleCreateGroup(c fiber.Ctx) error {
	var body struct {
		Name string `json:"name"`
	}
	if err := c.Bind().JSON(&body); err != nil || body.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name is required"})
	}

	group, err := store.CreateGroup(c.Context(), body.Name)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(group)
}

func handleListGroups(c fiber.Ctx) error {
	groups, err := store.ListGroups(c.Context())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(groups)
}

func handleGetGroup(c fiber.Ctx) error {
	group, err := store.GetGroup(c.Context(), c.Params("id"))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if group == nil {
		return c.Status(404).JSON(fiber.Map{"error": "group not found"})
	}
	return c.JSON(group)
}

func handleDeleteGroup(c fiber.Ctx) error {
	if err := store.DeleteGroup(c.Context(), c.Params("id")); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}

func handleAddPermissionToGroup(c fiber.Ctx) error {
	var body struct {
		PermissionKey string `json:"permission_key"`
	}
	if err := c.Bind().JSON(&body); err != nil || body.PermissionKey == "" {
		return c.Status(400).JSON(fiber.Map{"error": "permission_key is required"})
	}

	err := store.AddPermissionToGroup(c.Context(), c.Params("id"), body.PermissionKey)
	if errors.Is(err, auth.ErrPermissionNotFound) {
		return c.Status(404).JSON(fiber.Map{"error": "permission not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(fiber.Map{"message": "permission added to group"})
}

func handleRemovePermissionFromGroup(c fiber.Ctx) error {
	err := store.RemovePermissionFromGroup(c.Context(), c.Params("id"), c.Params("permId"))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}

// ─── User Management Handlers ───────────────────────────────

func handleListUsers(c fiber.Ctx) error {
	users, err := store.ListUsers(c.Context())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(users)
}

func handleGetUser(c fiber.Ctx) error {
	user, err := store.GetUserByID(c.Context(), c.Params("id"))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if user == nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}

	perms, err := store.GetResolvedPermissions(c.Context(), user.ID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	groups, err := store.GetUserGroups(c.Context(), user.ID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"user":        user,
		"permissions": perms,
		"groups":      groups,
	})
}

func handleAssignPermission(c fiber.Ctx) error {
	var body struct {
		PermissionKey string `json:"permission_key"`
	}
	if err := c.Bind().JSON(&body); err != nil || body.PermissionKey == "" {
		return c.Status(400).JSON(fiber.Map{"error": "permission_key is required"})
	}

	err := store.AssignPermission(c.Context(), c.Params("id"), body.PermissionKey)
	if errors.Is(err, auth.ErrPermissionNotFound) {
		return c.Status(404).JSON(fiber.Map{"error": "permission not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(fiber.Map{"message": "permission assigned"})
}

func handleRevokePermission(c fiber.Ctx) error {
	err := store.RevokePermission(c.Context(), c.Params("id"), c.Params("permKey"))
	if errors.Is(err, auth.ErrPermissionNotFound) {
		return c.Status(404).JSON(fiber.Map{"error": "permission not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}

func handleAssignUserToGroup(c fiber.Ctx) error {
	var body struct {
		GroupID string `json:"group_id"`
	}
	if err := c.Bind().JSON(&body); err != nil || body.GroupID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "group_id is required"})
	}

	err := store.AssignUserToGroup(c.Context(), c.Params("id"), body.GroupID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(fiber.Map{"message": "user added to group"})
}

func handleRemoveUserFromGroup(c fiber.Ctx) error {
	err := store.RemoveUserFromGroup(c.Context(), c.Params("id"), c.Params("groupId"))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}
