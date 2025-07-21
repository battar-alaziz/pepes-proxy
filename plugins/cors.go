package plugins

// CORSPlugin handles CORS headers
type CORSPlugin struct{}

func (p *CORSPlugin) Execute(ctx *PluginContext) *PluginResult {
	envs := parseEnvs(ctx.Envs)

	headers := make(map[string]string)

	// Set CORS headers
	origin := envs["cors_origin"]
	if origin == "" {
		origin = "*"
	}
	headers["Access-Control-Allow-Origin"] = origin

	if methods := envs["cors_methods"]; methods != "" {
		headers["Access-Control-Allow-Methods"] = methods
	} else {
		headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
	}

	if headersList := envs["cors_headers"]; headersList != "" {
		headers["Access-Control-Allow-Headers"] = headersList
	} else {
		headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
	}

	// Handle preflight requests
	if ctx.Method == "OPTIONS" {
		return &PluginResult{
			Success: true,
			Headers: headers,
		}
	}

	return &PluginResult{
		Success: true,
		Headers: headers,
	}
}
