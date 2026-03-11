package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateTokenPair creates a signed access token and refresh token for the given user.
// meta is optional — pass nil or a map of custom claims to embed in the access token (e.g. {"college_id": "xyz"}).
func GenerateTokenPair(cfg Config, user *User, permissions []string, groups []string, meta map[string]any) (*TokenPair, error) {
	accessToken, err := signToken(cfg.JWTSecret, user, "access", permissions, groups, meta, cfg.AccessExpiry)
	if err != nil {
		return nil, fmt.Errorf("auth: sign access token: %w", err)
	}

	refreshToken, err := signToken(cfg.JWTSecret, user, "refresh", nil, nil, nil, cfg.RefreshExpiry)
	if err != nil {
		return nil, fmt.Errorf("auth: sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RefreshTokenPair validates a refresh token and issues a new token pair.
// Fetches the latest user data and permissions from the store.
// Returns ErrUserNotFound if the user no longer exists.
func RefreshTokenPair(ctx context.Context, cfg Config, store Store, refreshToken string) (*TokenPair, error) {
	claims, err := ValidateToken(cfg, refreshToken)
	if err != nil {
		return nil, err
	}

	if claims.Type != "refresh" {
		return nil, fmt.Errorf("auth: token is not a refresh token")
	}

	user, err := store.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	perms, err := store.GetResolvedPermissions(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	permKeys := make([]string, len(perms))
	for i, p := range perms {
		permKeys[i] = p.Key
	}

	groups, err := store.GetUserGroups(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	groupNames := make([]string, len(groups))
	for i, g := range groups {
		groupNames[i] = g.Name
	}

	return GenerateTokenPair(cfg, user, permKeys, groupNames, nil)
}

// ValidateToken parses and validates a JWT token, returning the claims.
func ValidateToken(cfg Config, tokenStr string) (*Claims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("auth: invalid token: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("auth: invalid token claims")
	}

	claims := &Claims{
		UserID: mapClaims["user_id"].(string),
		Email:  mapClaims["email"].(string),
		Type:   mapClaims["type"].(string),
	}

	// Extract permissions if present (only in access tokens)
	if perms, ok := mapClaims["permissions"].([]interface{}); ok {
		claims.Permissions = make([]string, len(perms))
		for i, p := range perms {
			claims.Permissions[i] = p.(string)
		}
	}

	// Extract groups if present (only in access tokens)
	if grps, ok := mapClaims["groups"].([]interface{}); ok {
		claims.Groups = make([]string, len(grps))
		for i, g := range grps {
			claims.Groups[i] = g.(string)
		}
	}

	// Extract any remaining keys as meta (custom app-level claims)
	reserved := map[string]bool{"user_id": true, "email": true, "type": true, "iat": true, "exp": true, "permissions": true, "groups": true}
	for k, v := range mapClaims {
		if !reserved[k] {
			if claims.Meta == nil {
				claims.Meta = make(map[string]any)
			}
			claims.Meta[k] = v
		}
	}

	return claims, nil
}

func signToken(secret string, user *User, tokenType string, permissions []string, groups []string, meta map[string]any, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"type":    tokenType,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(expiry).Unix(),
	}

	// Only embed permissions, groups, and meta in access tokens
	if tokenType == "access" {
		if permissions != nil {
			claims["permissions"] = permissions
		}
		if groups != nil {
			claims["groups"] = groups
		}
		for k, v := range meta {
			claims[k] = v
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
