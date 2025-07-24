package plugins

// PluginContext represents the context passed to plugins
type PluginContext struct {
	Method   string
	Path     string
	Headers  map[string]string
	Body     string
	Envs     string
	ClientIP string
}

// PluginResult represents the result of plugin execution
type PluginResult struct {
	Success        bool
	Error          error
	Headers        map[string]string // Headers to add/modify
	HTTPStatusCode int               // HTTP status code to return on failure (e.g., 401, 403, 429)
}

// Plugin interface defines the contract for all plugins
type Plugin interface {
	Execute(ctx *PluginContext) *PluginResult
}
