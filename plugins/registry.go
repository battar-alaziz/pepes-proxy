package plugins

import "sync"

// PluginRegistry manages all available plugins
type PluginRegistry struct {
	plugins map[string]Plugin
	mutex   sync.RWMutex
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() *PluginRegistry {
	registry := &PluginRegistry{
		plugins: make(map[string]Plugin),
	}

	// Register built-in plugins
	registry.Register("jwt", &JWTPlugin{})
	registry.Register("ipwhitelist", &IPWhitelistPlugin{})
	registry.Register("ratelimit", &RateLimitPlugin{})
	registry.Register("cors", &CORSPlugin{})
	registry.Register("auth", &AuthPlugin{})
	registry.Register("logging", &LoggingPlugin{})

	return registry
}

// Register adds a plugin to the registry
func (pr *PluginRegistry) Register(name string, plugin Plugin) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	pr.plugins[name] = plugin
}

// Get retrieves a plugin from the registry
func (pr *PluginRegistry) Get(name string) (Plugin, bool) {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	plugin, exists := pr.plugins[name]
	return plugin, exists
}
