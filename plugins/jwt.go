package plugins

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTPlugin handles JWT token validation and forwarding
type JWTPlugin struct{}

func (p *JWTPlugin) Execute(ctx *PluginContext) *PluginResult {
	// Parse environment variables for JWT configuration
	envs := parseEnvs(ctx.Envs)

	// Get JWT secret from environment
	secret := envs["jwt_secret"]
	if secret == "" {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("jwt_secret not configured"),
			HTTPStatusCode: 500, // Internal server error for configuration issue
		}
	}

	// Get JWT token from Authorization header
	authHeader := ctx.Headers["Authorization"]
	if authHeader == "" {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("no authorization header"),
			HTTPStatusCode: 401,
		}
	}

	// Extract token from "Bearer <token>"
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("invalid authorization header format"),
			HTTPStatusCode: 401,
		}
	}

	token := tokenParts[1]

	// Validate JWT token
	claims, err := validateJWT(token, secret)
	if err != nil {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("invalid JWT token: %v", err),
			HTTPStatusCode: 401,
		}
	}

	// Forward sub claim to upstream
	headers := make(map[string]string)
	if sub, exists := claims["sub"]; exists {
		headers["X-User-Sub"] = fmt.Sprintf("%v", sub)
	}

	return &PluginResult{
		Success: true,
		Headers: headers,
	}
}

// validateJWT validates a JWT token and returns claims
func validateJWT(token, secret string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}

	// Parse payload
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid payload format")
	}

	// Check expiration
	if exp, exists := claims["exp"]; exists {
		if expFloat, ok := exp.(float64); ok {
			if time.Now().Unix() > int64(expFloat) {
				return nil, fmt.Errorf("token expired")
			}
		}
	}

	// Verify signature (simplified - in production use proper JWT library)
	message := parts[0] + "." + parts[1]
	expectedSig := hmac.New(sha256.New, []byte(secret))
	expectedSig.Write([]byte(message))
	expectedSigStr := base64.RawURLEncoding.EncodeToString(expectedSig.Sum(nil))

	if expectedSigStr != parts[2] {
		return nil, fmt.Errorf("invalid signature")
	}

	return claims, nil
}
