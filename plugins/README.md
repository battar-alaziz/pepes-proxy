# Plugins Package

This directory contains all the plugins for the Fast HTTP Proxy. Each plugin is implemented as a separate file and follows a common interface.

## Plugin Structure

### Interface

All plugins must implement the `Plugin` interface:

```go
type Plugin interface {
    Execute(ctx *PluginContext) *PluginResult
}
```

### PluginContext

The context passed to each plugin contains:

```go
type PluginContext struct {
    Method   string            // HTTP method (GET, POST, etc.)
    Path     string            // Request path
    Headers  map[string]string // Request headers
    Body     string            // Request body
    Envs     string            // Plugin configuration (key=value,key=value)
    ClientIP string            // Client IP address
}
```

### PluginResult

The result returned by each plugin:

```go
type PluginResult struct {
    Success        bool              // Whether plugin execution succeeded
    Error          error             // Error if execution failed
    Headers        map[string]string // Headers to add/modify
    HTTPStatusCode int               // HTTP status code to return on failure (e.g., 401, 403, 429)
}
```

**HTTPStatusCode Field:**
- Used only when `Success` is `false`
- Allows plugins to specify appropriate HTTP status codes:
  - `401` - Unauthorized (for authentication failures)
  - `403` - Forbidden (for authorization failures)
  - `429` - Too Many Requests (for rate limiting)
  - `500` - Internal Server Error (for configuration errors)
- If not specified (0), defaults to `403 Forbidden`

## Available Plugins

### 1. JWT Plugin (`jwt.go`)

Validates JWT tokens and forwards claims to upstream.

**Configuration:**
```
jwt_secret=your-secret-key
```

**Features:**
- Validates JWT tokens from Authorization header
- Checks token expiration
- Forwards `sub` claim as `X-User-Sub` header

### 2. IP Whitelist Plugin (`ipwhitelist.go`)

Restricts access based on client IP addresses.

**Configuration:**
```
whitelist_ips=192.168.1.1,10.0.0.1,127.0.0.1
```

**Features:**
- Comma-separated list of allowed IPs
- Blocks requests from non-whitelisted IPs

### 3. Rate Limit Plugin (`ratelimit.go`)

Implements rate limiting per client IP.

**Configuration:**
```
rate_limit=100,rate_window=60
```

**Features:**
- Configurable request limit per time window
- Sliding window algorithm
- Default window is 60 seconds

### 4. CORS Plugin (`cors.go`)

Handles Cross-Origin Resource Sharing headers.

**Configuration:**
```
cors_origin=*,cors_methods=GET,POST,PUT,DELETE,OPTIONS,cors_headers=Content-Type,Authorization
```

**Features:**
- Configurable origin, methods, and headers
- Handles preflight OPTIONS requests

### 5. Authentication Plugin (`auth.go`)

Implements basic HTTP authentication.

**Configuration:**
```
auth_user=admin,auth_pass=password
```

**Features:**
- Basic HTTP authentication
- Configurable username and password

### 6. Logging Plugin (`logging.go`)

Provides request logging functionality.

**Configuration:**
```
log_level=info
```

**Features:**
- Configurable log levels (info, debug)
- Logs request method, path, and client IP

## Creating a New Plugin

To create a new plugin:

1. **Create a new file** in the `plugins` directory (e.g., `myplugin.go`)

2. **Implement the Plugin interface:**

```go
package plugins

import "fmt"

// MyPlugin handles custom functionality
type MyPlugin struct{}

func (p *MyPlugin) Execute(ctx *PluginContext) *PluginResult {
    // Parse configuration
    envs := parseEnvs(ctx.Envs)
    
    // Your plugin logic here
    customValue := envs["custom_key"]
    if customValue == "" {
        return &PluginResult{
            Success:        false,
            Error:          fmt.Errorf("custom_key not configured"),
            HTTPStatusCode: 500, // Internal server error for configuration issue
        }
    }
    
    // Add custom headers if needed
    headers := make(map[string]string)
    headers["X-Custom-Header"] = customValue
    
    return &PluginResult{
        Success: true,
        Headers: headers,
    }
}
```

3. **Register the plugin** in `registry.go`:

```go
// In NewPluginRegistry() function
registry.Register("myplugin", &MyPlugin{})
```

4. **Add tests** in the main test file:

```go
func TestMyPlugin(t *testing.T) {
    plugin := &plugins.MyPlugin{}
    
    ctx := &plugins.PluginContext{
        Method:   "GET",
        Path:     "/api",
        Headers:  map[string]string{},
        Body:     "",
        Envs:     "custom_key=test-value",
        ClientIP: "127.0.0.1",
    }
    
    result := plugin.Execute(ctx)
    if !result.Success {
        t.Error("Expected success")
    }
}
```

## Plugin Execution Flow

1. **Request comes in** to the proxy
2. **Plugin context is created** with request details
3. **Plugins are executed** in order from configuration
4. **Each plugin can:**
   - Validate the request
   - Modify headers
   - Block the request (return Success: false)
   - Pass the request to the next plugin
5. **Headers from all plugins** are merged and forwarded to upstream

## Configuration Format

Plugin configuration uses a simple key-value format:

```
key1=value1,key2=value2,key3=value3
```

Use the `parseEnvs()` function to parse configuration:

```go
envs := parseEnvs(ctx.Envs)
value := envs["my_key"]
```

## Best Practices

1. **Always check configuration** - Return an error if required configuration is missing
2. **Use descriptive error messages** - Help with debugging
3. **Be efficient** - Plugins are executed for every request
4. **Handle edge cases** - Consider what happens with malformed input
5. **Add tests** - Ensure your plugin works correctly
6. **Document configuration** - Explain what each configuration option does

## Testing Plugins

Each plugin should have comprehensive tests covering:

- Success scenarios
- Failure scenarios
- Edge cases
- Configuration validation
- Header modification

Run tests with:

```bash
go test -v
```

## Performance Considerations

- Plugins are executed synchronously for each request
- Keep plugin logic lightweight and efficient
- Avoid expensive operations (database queries, network calls)
- Use caching when appropriate
- Consider the impact on request latency 