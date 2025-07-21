package main

import (
	"testing"

	"github.com/deployaja/proxy-go/plugins"
)

func TestParseEnvs(t *testing.T) {
	// This test is now in the plugins package
	// We'll test it through the plugin execution
}

func TestJWTPlugin(t *testing.T) {
	plugin := &plugins.JWTPlugin{}

	// Test with missing secret
	ctx := &plugins.PluginContext{
		Method:   "GET",
		Path:     "/api",
		Headers:  map[string]string{},
		Body:     "",
		Envs:     "",
		ClientIP: "127.0.0.1",
	}

	result := plugin.Execute(ctx)
	if result.Success {
		t.Error("Expected failure when no JWT secret configured")
	}

	// Test with missing authorization header
	ctx.Envs = "jwt_secret=test-secret"
	result = plugin.Execute(ctx)
	if result.Success {
		t.Error("Expected failure when no Authorization header")
	}
}

func TestIPWhitelistPlugin(t *testing.T) {
	plugin := &plugins.IPWhitelistPlugin{}

	// Test with no whitelist configured
	ctx := &plugins.PluginContext{
		Method:   "GET",
		Path:     "/api",
		Headers:  map[string]string{},
		Body:     "",
		Envs:     "",
		ClientIP: "127.0.0.1",
	}

	result := plugin.Execute(ctx)
	if !result.Success {
		t.Error("Expected success when no whitelist configured")
	}

	// Test with whitelisted IP
	ctx.Envs = "whitelist_ips=127.0.0.1,192.168.1.1"
	result = plugin.Execute(ctx)
	if !result.Success {
		t.Error("Expected success for whitelisted IP")
	}

	// Test with non-whitelisted IP
	ctx.ClientIP = "10.0.0.1"
	result = plugin.Execute(ctx)
	if result.Success {
		t.Error("Expected failure for non-whitelisted IP")
	}
}

func TestRateLimitPlugin(t *testing.T) {
	plugin := &plugins.RateLimitPlugin{}

	// Test with no rate limit configured
	ctx := &plugins.PluginContext{
		Method:   "GET",
		Path:     "/api",
		Headers:  map[string]string{},
		Body:     "",
		Envs:     "",
		ClientIP: "127.0.0.1",
	}

	result := plugin.Execute(ctx)
	if !result.Success {
		t.Error("Expected success when no rate limit configured")
	}

	// Test with rate limit configured
	ctx.Envs = "rate_limit=1,rate_window=60"
	result = plugin.Execute(ctx)
	if !result.Success {
		t.Error("Expected success for first request")
	}

	// Second request should be rate limited
	result = plugin.Execute(ctx)
	if result.Success {
		t.Error("Expected failure for second request (rate limited)")
	}
}

func TestCORSPlugin(t *testing.T) {
	plugin := &plugins.CORSPlugin{}

	// Test with default settings
	ctx := &plugins.PluginContext{
		Method:   "GET",
		Path:     "/api",
		Headers:  map[string]string{},
		Body:     "",
		Envs:     "",
		ClientIP: "127.0.0.1",
	}

	result := plugin.Execute(ctx)
	if !result.Success {
		t.Error("Expected success for CORS plugin")
	}

	// Check that CORS headers are added
	if result.Headers["Access-Control-Allow-Origin"] != "*" {
		t.Error("Expected Access-Control-Allow-Origin header")
	}

	// Test OPTIONS request
	ctx.Method = "OPTIONS"
	result = plugin.Execute(ctx)
	if !result.Success {
		t.Error("Expected success for OPTIONS request")
	}
}

func TestAuthPlugin(t *testing.T) {
	plugin := &plugins.AuthPlugin{}

	// Test with no auth configured
	ctx := &plugins.PluginContext{
		Method:   "GET",
		Path:     "/api",
		Headers:  map[string]string{},
		Body:     "",
		Envs:     "",
		ClientIP: "127.0.0.1",
	}

	result := plugin.Execute(ctx)
	if !result.Success {
		t.Error("Expected success when no auth configured")
	}

	// Test with auth configured but no header
	ctx.Envs = "auth_user=admin,auth_pass=password"
	result = plugin.Execute(ctx)
	if result.Success {
		t.Error("Expected failure when no Authorization header")
	}
}

func TestLoggingPlugin(t *testing.T) {
	plugin := &plugins.LoggingPlugin{}

	ctx := &plugins.PluginContext{
		Method:   "GET",
		Path:     "/api",
		Headers:  map[string]string{"User-Agent": "test"},
		Body:     "",
		Envs:     "log_level=info",
		ClientIP: "127.0.0.1",
	}

	result := plugin.Execute(ctx)
	if !result.Success {
		t.Error("Expected success for logging plugin")
	}
}

func TestPluginRegistry(t *testing.T) {
	registry := plugins.NewPluginRegistry()

	// Test that built-in plugins are registered
	pluginNames := []string{"jwt", "ipwhitelist", "ratelimit", "cors", "auth", "logging"}

	for _, pluginName := range pluginNames {
		plugin, exists := registry.Get(pluginName)
		if !exists {
			t.Errorf("Expected plugin %s to be registered", pluginName)
		}
		if plugin == nil {
			t.Errorf("Expected plugin %s to not be nil", pluginName)
		}
	}

	// Test non-existent plugin
	_, exists := registry.Get("nonexistent")
	if exists {
		t.Error("Expected non-existent plugin to not exist")
	}
}
