package plugins

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// AuthPlugin handles basic authentication
type AuthPlugin struct{}

func (p *AuthPlugin) Execute(ctx *PluginContext) *PluginResult {
	envs := parseEnvs(ctx.Envs)

	// Get expected credentials
	expectedUser := envs["auth_user"]
	expectedPass := envs["auth_pass"]

	if expectedUser == "" || expectedPass == "" {
		return &PluginResult{Success: true} // No auth configured
	}

	// Get Authorization header
	authHeader := ctx.Headers["Authorization"]
	if authHeader == "" {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("no authorization header"),
			HTTPStatusCode: 401,
			Headers: map[string]string{
				"WWW-Authenticate": `Basic realm="Protected Area"`,
			},
		}
	}

	// Parse Basic Auth
	if !strings.HasPrefix(authHeader, "Basic ") {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("invalid authorization header"),
			HTTPStatusCode: 401,
			Headers: map[string]string{
				"WWW-Authenticate": `Basic realm="Protected Area"`,
			},
		}
	}

	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("invalid base64 encoding"),
			HTTPStatusCode: 401,
			Headers: map[string]string{
				"WWW-Authenticate": `Basic realm="Protected Area"`,
			},
		}
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("invalid credentials format"),
			HTTPStatusCode: 401,
			Headers: map[string]string{
				"WWW-Authenticate": `Basic realm="Protected Area"`,
			},
		}
	}

	user, pass := credentials[0], credentials[1]

	if user != expectedUser || pass != expectedPass {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("invalid credentials"),
			HTTPStatusCode: 401,
			Headers: map[string]string{
				"WWW-Authenticate": `Basic realm="Protected Area"`,
			},
		}
	}

	return &PluginResult{Success: true}
}
