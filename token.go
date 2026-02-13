package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateTokenPair creates a signed access token and refresh token for the given user with embedded permissions.
func GenerateTokenPair(cfg Config, user *User, permissions []string) (*TokenPair, error) {
	accessToken, err := signToken(cfg.JWTSecret, user, "access", permissions, cfg.AccessExpiry)
	if err != nil {
		return nil, fmt.Errorf("auth: sign access token: %w", err)
	}

	refreshToken, err := signToken(cfg.JWTSecret, user, "refresh", nil, cfg.RefreshExpiry)
	if err != nil {
		return nil, fmt.Errorf("auth: sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
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

	return claims, nil
}

func signToken(secret string, user *User, tokenType string, permissions []string, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"type":    tokenType,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(expiry).Unix(),
	}

	// Only embed permissions in access tokens
	if tokenType == "access" && permissions != nil {
		claims["permissions"] = permissions
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
