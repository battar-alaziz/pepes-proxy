# Fast HTTP Proxy with Plugin System

A high-performance HTTP proxy server written in Go with a flexible plugin architecture for request processing.

## Features

- **High Performance**: Built with fasthttp for optimal performance
- **Plugin Architecture**: Extensible plugin system for request processing
- **Configuration Management**: Dynamic configuration updates via API
- **Connection Pooling**: Efficient connection reuse
- **HTTPS Support**: Full HTTPS tunneling support
- **Built-in Plugins**: JWT validation, IP whitelisting, rate limiting, CORS, authentication, and logging

## Built-in Plugins

### 1. JWT Plugin (`jwt`)

Validates JWT tokens and forwards the `sub` claim to upstream services.

**Configuration:**
```
envs: "jwt_secret=your-secret-key"
```

**Features:**
- Validates JWT tokens from Authorization header
- Checks token expiration
- Forwards `sub` claim as `X-User-Sub` header to upstream
- Supports HMAC-SHA256 signature verification

**Example:**
```json
{
  "name_plugin": "jwt",
  "envs": "jwt_secret=my-secret-key"
}
```

### 2. IP Whitelist Plugin (`ipwhitelist`)

Restricts access based on client IP addresses.

**Configuration:**
```
envs: "whitelist_ips=192.168.1.1,10.0.0.1,127.0.0.1"
```

**Features:**
- Comma-separated list of allowed IP addresses
- Blocks requests from non-whitelisted IPs
- Returns 403 Forbidden for blocked requests

**Example:**
```json
{
  "name_plugin": "ipwhitelist",
  "envs": "whitelist_ips=192.168.1.1,10.0.0.1"
}
```

### 3. Rate Limit Plugin (`ratelimit`)

Implements rate limiting per client IP.

**Configuration:**
```
envs: "rate_limit=100,rate_window=60"
```

**Features:**
- Configurable request limit per time window
- Default window is 60 seconds
- Uses sliding window algorithm
- Returns 403 Forbidden when limit exceeded

**Example:**
```json
{
  "name_plugin": "ratelimit",
  "envs": "rate_limit=100,rate_window=60"
}
```

### 4. CORS Plugin (`cors`)

Handles Cross-Origin Resource Sharing headers.

**Configuration:**
```
envs: "cors_origin=*,cors_methods=GET,POST,PUT,DELETE,cors_headers=Content-Type,Authorization"
```

**Features:**
- Configurable origin, methods, and headers
- Handles preflight OPTIONS requests
- Defaults to permissive settings if not configured

**Example:**
```json
{
  "name_plugin": "cors",
  "envs": "cors_origin=https://example.com,cors_methods=GET,POST"
}
```

### 5. Authentication Plugin (`auth`)

Implements basic HTTP authentication.

**Configuration:**
```
envs: "auth_user=admin,auth_pass=password"
```

**Features:**
- Basic HTTP authentication
- Configurable username and password
- Returns 401 Unauthorized for invalid credentials

**Example:**
```json
{
  "name_plugin": "auth",
  "envs": "auth_user=admin,auth_pass=secret123"
}
```

### 6. Logging Plugin (`logging`)

Provides request logging functionality.

**Configuration:**
```
envs: "log_level=info"
```

**Features:**
- Configurable log levels (info, debug)
- Logs request method, path, and client IP
- Debug level includes request headers

**Example:**
```json
{
  "name_plugin": "logging",
  "envs": "log_level=debug"
}
```

## Configuration

The proxy fetches configuration from an API endpoint. The configuration structure is:

```json
{
  "domains": {
    "example.com": {
      "routes": [
        {
          "path": "/api",
          "upstream": "backend-service:8080",
          "plugins_data": [
            {
              "id": 1,
              "name_plugin": "jwt",
              "envs": "jwt_secret=my-secret",
              "desc": "JWT validation",
              "created_at": "2024-01-01T00:00:00Z",
              "updated_at": "2024-01-01T00:00:00Z",
              "deleted_at": null
            },
            {
              "id": 2,
              "name_plugin": "ratelimit",
              "envs": "rate_limit=100,rate_window=60",
              "desc": "Rate limiting",
              "created_at": "2024-01-01T00:00:00Z",
              "updated_at": "2024-01-01T00:00:00Z",
              "deleted_at": null
            }
          ]
        }
      ]
    }
  }
}
```

## Environment Variables

- `PROXY_PORT`: Port to run the proxy on (default: 8070)
- `SIDRA_API`: URL of the configuration API (default: http://localhost:8081)

## Usage

### Running the Proxy

```bash
# Using default settings
go run main.go

# With custom port
PROXY_PORT=8080 go run main.go

# With custom configuration API
SIDRA_API=http://config-api:8081 go run main.go
```

### Using with curl

```bash
# Basic proxy usage
curl -x http://localhost:8070 http://example.com/api

# With JWT token
curl -x http://localhost:8070 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  http://example.com/api

# With basic auth
curl -x http://localhost:8070 \
  -u "admin:password" \
  http://example.com/api
```

## Plugin Development

To create a custom plugin, implement the `Plugin` interface:

```go
type Plugin interface {
    Execute(ctx *PluginContext) *PluginResult
}
```

### PluginContext

```go
type PluginContext struct {
    Method   string            // HTTP method
    Path     string            // Request path
    Headers  map[string]string // Request headers
    Body     string            // Request body
    Envs     string            // Plugin configuration
    ClientIP string            // Client IP address
}
```

### PluginResult

```go
type PluginResult struct {
    Success bool              // Whether plugin execution succeeded
    Error   error             // Error if execution failed
    Headers map[string]string // Headers to add/modify
}
```

### Example Custom Plugin

```go
type CustomPlugin struct{}

func (p *CustomPlugin) Execute(ctx *PluginContext) *PluginResult {
    // Parse configuration
    envs := parseEnvs(ctx.Envs)
    
    // Your plugin logic here
    if ctx.Method == "POST" {
        // Add custom header
        headers := map[string]string{
            "X-Custom-Header": "custom-value",
        }
        
        return &PluginResult{
            Success: true,
            Headers: headers,
        }
    }
    
    return &PluginResult{Success: true}
}

// Register the plugin
registry.Register("custom", &CustomPlugin{})
```

## Architecture

The proxy uses a plugin pipeline where each plugin can:
1. Validate the request
2. Modify request headers
3. Block the request (return false)
4. Pass the request to the next plugin

Plugins are executed in the order they appear in the configuration, and any plugin can stop the request flow by returning `Success: false`.

## Performance

- Built with fasthttp for high performance
- Connection pooling for efficient resource usage
- Plugin execution is synchronous but fast
- Configuration updates every 15 seconds
- Minimal memory footprint

## Security

- JWT token validation with HMAC-SHA256
- IP-based access control
- Rate limiting to prevent abuse
- Basic authentication support
- HTTPS tunneling support

## Monitoring

The proxy logs:
- Request details (method, path, client IP)
- Plugin execution results
- Configuration updates
- Error conditions

Log level can be configured per plugin using the logging plugin. 