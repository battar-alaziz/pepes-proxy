package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deployaja/proxy-go/plugins"
	"github.com/valyala/fasthttp"
)

// Config represents the configuration structure
type Config struct {
	Domains map[string]DomainConfig `json:"domains"`
}

// DomainConfig represents domain-specific configuration
type DomainConfig struct {
	Routes []Route `json:"routes"`
}

// Route represents a route configuration
type Route struct {
	Path        string       `json:"path"`
	Upstream    string       `json:"upstream"`
	Plugin      string       `json:"plugin"`
	PluginsData []PluginData `json:"plugins_data"`
}

// PluginData represents plugin configuration data
type PluginData struct {
	ID            int     `json:"id"`
	NamePlugin    string  `json:"name_plugin"`
	PluginSvcName string  `json:"plugin_svc_name"`
	Envs          string  `json:"envs"`
	Desc          string  `json:"desc"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	DeletedAt     *string `json:"deleted_at"`
}

// ProxyServer represents our HTTP proxy server
type ProxyServer struct {
	addr     string
	listener net.Listener
	pool     *ConnectionPool
	client   *fasthttp.Client
	config   *Config
	configMu sync.RWMutex
	plugins  *plugins.PluginRegistry
}

// ConnectionPool manages reusable connections
type ConnectionPool struct {
	connections map[string][]net.Conn
	mutex       sync.RWMutex
	maxIdle     int
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxIdle int) *ConnectionPool {
	return &ConnectionPool{
		connections: make(map[string][]net.Conn),
		maxIdle:     maxIdle,
	}
}

// GetConnection retrieves a connection from the pool
func (p *ConnectionPool) GetConnection(target string) net.Conn {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if conns, exists := p.connections[target]; exists && len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.connections[target] = conns[:len(conns)-1]
		return conn
	}
	return nil
}

// PutConnection returns a connection to the pool
func (p *ConnectionPool) PutConnection(target string, conn net.Conn) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(p.connections[target]) < p.maxIdle {
		p.connections[target] = append(p.connections[target], conn)
	} else {
		conn.Close()
	}
}

// NewProxyServer creates a new proxy server
func NewProxyServer(addr string) *ProxyServer {
	ps := &ProxyServer{
		addr: addr,
		pool: NewConnectionPool(10), // Max 10 idle connections per target
		client: &fasthttp.Client{
			ReadTimeout:         30 * time.Second,
			WriteTimeout:        30 * time.Second,
			MaxIdleConnDuration: 90 * time.Second,
			MaxConnsPerHost:     1000,
		},
		config: &Config{
			Domains: make(map[string]DomainConfig),
		},
		plugins: plugins.NewPluginRegistry(),
	}

	// Start configuration scheduler
	go ps.startConfigScheduler()

	return ps
}

// startConfigScheduler starts the configuration update scheduler
func (ps *ProxyServer) startConfigScheduler() {
	// Fetch initial config
	ps.fetchConfig()

	// Schedule updates every 15 seconds
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ps.fetchConfig()
	}
}

// fetchConfig fetches configuration from the API
func (ps *ProxyServer) fetchConfig() {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Get sidra-api URL from environment variable or use default
	sidraAPI := os.Getenv("SIDRA_API")
	if sidraAPI == "" {
		sidraAPI = "http://pinus-api"
	}

	req.SetRequestURI(sidraAPI + "/config")
	req.Header.SetMethod("GET")

	if err := ps.client.Do(req, resp); err != nil {
		log.Printf("Error fetching config: %v", err)
		return
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		log.Printf("Error fetching config: status %d", resp.StatusCode())
		return
	}

	var newConfig Config
	if err := json.Unmarshal(resp.Body(), &newConfig); err != nil {
		log.Printf("Error parsing config: %v", err)
		return
	}

	// Update config with thread safety
	ps.configMu.Lock()
	ps.config = &newConfig
	ps.configMu.Unlock()

	log.Printf("Configuration updated successfully")
}

// GetConfig returns a copy of the current configuration
func (ps *ProxyServer) GetConfig() *Config {
	ps.configMu.RLock()
	defer ps.configMu.RUnlock()

	// Return a copy to avoid race conditions
	configCopy := &Config{
		Domains: make(map[string]DomainConfig),
	}

	for domain, domainConfig := range ps.config.Domains {
		configCopy.Domains[domain] = domainConfig
	}

	return configCopy
}

// getDomainConfig returns configuration for a specific domain
func (ps *ProxyServer) getDomainConfig(domain string) (DomainConfig, bool) {
	ps.configMu.RLock()
	defer ps.configMu.RUnlock()

	domainConfig, exists := ps.config.Domains[domain]
	return domainConfig, exists
}

// logCurrentConfig logs the current configuration for debugging
func (ps *ProxyServer) logCurrentConfig() {
	config := ps.GetConfig()
	log.Printf("Current configuration: %d domains configured", len(config.Domains))
	for domain, domainConfig := range config.Domains {
		log.Printf("Domain: %s, Routes: %d", domain, len(domainConfig.Routes))
		for _, route := range domainConfig.Routes {
			log.Printf("  - Path: %s, Upstream: %s, Plugins: %d", route.Path, route.Upstream, len(route.PluginsData))
			for _, plugin := range route.PluginsData {
				if plugin.DeletedAt == nil {
					log.Printf("    * Plugin: %s (service: %s)", plugin.NamePlugin, plugin.PluginSvcName)
				}
			}
		}
	}
}

// Start starts the proxy server
func (ps *ProxyServer) Start() error {
	var err error
	ps.listener, err = net.Listen("tcp", ps.addr)
	if err != nil {
		return fmt.Errorf("failed to start proxy: %v", err)
	}

	log.Printf("Fast HTTP Proxy started on %s", ps.addr)

	for {
		conn, err := ps.listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go ps.handleConnection(conn)
	}
}

// handleConnection handles a new client connection
func (ps *ProxyServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set read timeout
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Create a buffered reader
	reader := bufio.NewReader(clientConn)

	// Read the first line to determine the method
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading first line: %v", err)
		return
	}

	// Parse the first line
	parts := strings.Fields(strings.TrimSpace(firstLine))
	if len(parts) < 3 {
		log.Printf("Invalid request line: %s", firstLine)
		return
	}

	method := parts[0]
	target := parts[1]

	// Handle CONNECT method for HTTPS tunneling
	if method == "CONNECT" {
		ps.handleHTTPS(clientConn, target, reader)
		return
	}

	// For HTTP requests, we need to reconstruct the request since we consumed the first line
	ps.handleHTTPWithFirstLine(clientConn, reader, firstLine)
}

// handleHTTPS handles HTTPS tunneling via CONNECT method
func (ps *ProxyServer) handleHTTPS(clientConn net.Conn, target string, reader *bufio.Reader) {
	// Connect to target server
	targetConn, err := ps.getTargetConnection(target)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", target, err)
		clientConn.Write([]byte(getHTTPStatusResponse(502)))
		return
	}
	defer targetConn.Close()

	// Send success response to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// Start bidirectional tunneling
	ps.tunnel(clientConn, targetConn)
}

// executePlugins executes plugins for a given route and returns true if all plugins succeed
func (ps *ProxyServer) executePlugins(route Route, originalReq *fasthttp.Request, clientIP string) (bool, map[string]string, int, error) {
	// Check if we have plugins_data
	if len(route.PluginsData) == 0 {
		return true, nil, 0, nil // No plugins configured, continue
	}

	log.Printf("Plugin configuration: %d plugins found", len(route.PluginsData))

	// Collect headers from all plugins
	pluginHeaders := make(map[string]string)

	for _, pluginData := range route.PluginsData {
		// Skip if plugin is deleted
		if pluginData.DeletedAt != nil {
			log.Printf("Skipping deleted plugin: %s", pluginData.NamePlugin)
			continue
		}

		// Get plugin by name
		plugin, exists := ps.plugins.Get(pluginData.NamePlugin)
		if !exists {
			log.Printf("Warning: plugin '%s' not found, skipping", pluginData.NamePlugin)
			continue
		}

		// Extract headers from request
		headers := make(map[string]string)
		originalReq.Header.VisitAll(func(key, value []byte) {
			headers[string(key)] = string(value)
		})

		// Create plugin context
		ctx := &plugins.PluginContext{
			Method:   string(originalReq.Header.Method()),
			Path:     string(originalReq.RequestURI()),
			Headers:  headers,
			Body:     string(originalReq.Body()),
			Envs:     pluginData.Envs,
			ClientIP: clientIP,
		}

		// Execute plugin
		log.Printf("Executing plugin: %s", pluginData.NamePlugin)
		result := plugin.Execute(ctx)

		if !result.Success {
			log.Printf("Plugin %s failed: %v", pluginData.NamePlugin, result.Error)
			// Use plugin-specified status code, or default to 403 if not specified
			statusCode := result.HTTPStatusCode
			if statusCode == 0 {
				statusCode = 403 // Default to Forbidden
			}
			// Return plugin headers from the failed plugin so they can be sent to client
			return false, result.Headers, statusCode, result.Error
		}

		// Merge headers from plugin
		for key, value := range result.Headers {
			pluginHeaders[key] = value
		}

		log.Printf("Plugin %s executed successfully", pluginData.NamePlugin)
	}

	return true, pluginHeaders, 0, nil
}

// findMatchingRoute finds the matching route for a given domain and path
func (ps *ProxyServer) findMatchingRoute(domain, path string) (Route, bool) {
	domainConfig, exists := ps.getDomainConfig(domain)
	if !exists {
		return Route{}, false
	}

	// Find matching route based on path
	for _, route := range domainConfig.Routes {
		if strings.HasPrefix(path, route.Path) {
			return route, true
		}
	}

	return Route{}, false
}

// handleHTTPWithFirstLine handles HTTP requests when the first line has already been read
func (ps *ProxyServer) handleHTTPWithFirstLine(clientConn net.Conn, reader *bufio.Reader, firstLine string) {
	// Create a new reader that includes the first line
	combinedReader := io.MultiReader(
		strings.NewReader(firstLine),
		reader,
	)

	// Create a buffered reader from the combined reader
	bufferedReader := bufio.NewReader(combinedReader)

	// Read the entire request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Read request line and headers
	if err := req.ReadLimitBody(bufferedReader, 1024*1024); err != nil { // 1MB limit
		log.Printf("Error reading HTTP request: %v", err)
		return
	}

	// Extract domain from Host header
	host := string(req.Header.Peek("Host"))
	if host == "" {
		log.Printf("No Host header found")
		clientConn.Write([]byte(getHTTPStatusResponse(400)))
		return
	}

	// Remove port if present
	domain := host
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		domain = host[:colonIndex]
	}

	// Get path from request
	path := string(req.RequestURI())

	log.Printf("Request for domain: %s, path: %s", domain, path)

	// Find matching route
	route, found := ps.findMatchingRoute(domain, path)
	if !found {
		log.Printf("No matching route found for domain: %s, path: %s", domain, path)
		clientConn.Write([]byte(getHTTPStatusResponse(404)))
		return
	}

	log.Printf("Found route: upstream=%s, plugins=%d", route.Upstream, len(route.PluginsData))

	// Execute plugins if configured
	if len(route.PluginsData) > 0 {
		pluginSuccess, pluginHeaders, statusCode, err := ps.executePlugins(route, req, getClientIP(clientConn))
		if err != nil || !pluginSuccess {
			log.Printf("Error executing plugins: %v", err)
			clientConn.Write([]byte(getHTTPStatusResponseWithHeaders(statusCode, pluginHeaders)))
			return
		}

		// Add plugin headers to request
		for key, value := range pluginHeaders {
			req.Header.Set(key, value)
		}
	}

	// Forward request to upstream
	ps.forwardToUpstream(clientConn, req, route.Upstream)
}

// handleHTTP handles regular HTTP requests using fasthttp
func (ps *ProxyServer) handleHTTP(clientConn net.Conn, reader *bufio.Reader) {
	// Read the entire request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Read request line and headers
	if err := req.ReadLimitBody(reader, 1024*1024); err != nil { // 1MB limit
		log.Printf("Error reading HTTP request: %v", err)
		return
	}

	// Extract domain from Host header
	host := string(req.Header.Peek("Host"))
	if host == "" {
		log.Printf("No Host header found")
		clientConn.Write([]byte(getHTTPStatusResponse(400)))
		return
	}

	// Remove port if present
	domain := host
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		domain = host[:colonIndex]
	}

	// Get path from request
	path := string(req.RequestURI())

	log.Printf("Request for domain: %s, path: %s", domain, path)

	// Find matching route
	route, found := ps.findMatchingRoute(domain, path)
	if !found {
		log.Printf("No matching route found for domain: %s, path: %s", domain, path)
		clientConn.Write([]byte(getHTTPStatusResponse(404)))
		return
	}

	log.Printf("Found route: upstream=%s, plugins=%d", route.Upstream, len(route.PluginsData))

	// Get client IP
	clientIP := getClientIP(clientConn)

	// Execute plugins if configured
	if len(route.PluginsData) > 0 {
		pluginSuccess, pluginHeaders, statusCode, err := ps.executePlugins(route, req, clientIP)
		if err != nil || !pluginSuccess {
			log.Printf("Error executing plugins: %v", err)
			clientConn.Write([]byte(getHTTPStatusResponseWithHeaders(statusCode, pluginHeaders)))
			return
		}

		// Add plugin headers to request
		for key, value := range pluginHeaders {
			req.Header.Set(key, value)
		}
	}

	// Forward request to upstream
	ps.forwardToUpstream(clientConn, req, route.Upstream)
}

// forwardToUpstream forwards the request to the configured upstream
func (ps *ProxyServer) forwardToUpstream(clientConn net.Conn, originalReq *fasthttp.Request, upstream string) {
	// Create a new request for upstream
	newReq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(newReq)

	// Copy method
	newReq.Header.SetMethod(string(originalReq.Header.Method()))

	// Copy headers
	originalReq.Header.VisitAll(func(key, value []byte) {
		newReq.Header.SetBytesKV(key, value)
	})

	// Set proper host header for upstream
	newReq.Header.SetHost(upstream)

	// Set the target URL (use original path)
	newReq.SetRequestURI(string(originalReq.RequestURI()))

	// Copy body if present
	if originalReq.Body() != nil {
		newReq.SetBody(originalReq.Body())
	}

	// Create response
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Make the request to upstream
	upstreamURL := upstream
	if !strings.HasPrefix(upstream, "http://") && !strings.HasPrefix(upstream, "https://") {
		upstreamURL = "http://" + upstream
	}

	// Set the full URL for upstream
	fullURL := upstreamURL + string(originalReq.RequestURI())
	newReq.SetRequestURI(fullURL)

	log.Printf("Forwarding request to upstream: %s", upstreamURL)

	if err := ps.client.Do(newReq, resp); err != nil {
		log.Printf("Error making request to upstream: %v", err)
		clientConn.Write([]byte(getHTTPStatusResponse(502)))
		return
	}

	// Write response back to client
	resp.WriteTo(clientConn)
}

// getTargetConnection gets a connection to the target server
func (ps *ProxyServer) getTargetConnection(target string) (net.Conn, error) {
	// Try to get from pool first
	if conn := ps.pool.GetConnection(target); conn != nil {
		// Test if connection is still alive
		if err := ps.testConnection(conn); err == nil {
			return conn, nil
		}
		conn.Close()
	}

	// Create new connection
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// testConnection tests if a connection is still alive
func (ps *ProxyServer) testConnection(conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	return err
}

// tunnel performs bidirectional tunneling between client and target
func (ps *ProxyServer) tunnel(clientConn, targetConn net.Conn) {
	// Create channels for coordination
	done := make(chan bool, 2)

	// Copy from client to target
	go func() {
		io.Copy(targetConn, clientConn)
		done <- true
	}()

	// Copy from target to client
	go func() {
		io.Copy(clientConn, targetConn)
		done <- true
	}()

	// Wait for either direction to finish
	<-done
}

// Helper functions

// getHTTPStatusResponse returns the appropriate HTTP response string for a status code
func getHTTPStatusResponse(statusCode int) string {
	return getHTTPStatusResponseWithHeaders(statusCode, nil)
}

// getHTTPStatusResponseWithHeaders returns the appropriate HTTP response string for a status code with custom headers
func getHTTPStatusResponseWithHeaders(statusCode int, customHeaders map[string]string) string {
	var title, message, description string

	switch statusCode {
	case 400:
		title = "400 Bad Request"
		message = "Bad Request"
		description = "The server cannot process your request due to invalid syntax."
	case 401:
		title = "401 Unauthorized"
		message = "Authentication Required"
		description = "You need to provide valid credentials to access this resource."
	case 403:
		title = "403 Forbidden"
		message = "Access Denied"
		description = "You don't have permission to access this resource."
	case 404:
		title = "404 Not Found"
		message = "Page Not Found"
		description = "The requested resource could not be found on this server."
	case 429:
		title = "429 Too Many Requests"
		message = "Rate Limit Exceeded"
		description = "You have sent too many requests in a given amount of time. Please try again later."
	case 500:
		title = "500 Internal Server Error"
		message = "Internal Server Error"
		description = "The server encountered an unexpected condition that prevented it from fulfilling the request."
	case 502:
		title = "502 Bad Gateway"
		message = "Bad Gateway"
		description = "The server received an invalid response from the upstream server."
	case 503:
		title = "503 Service Unavailable"
		message = "Service Unavailable"
		description = "The server is temporarily unable to handle the request due to maintenance or capacity problems."
	default:
		title = "403 Forbidden"
		message = "Access Denied"
		description = "You don't have permission to access this resource."
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        
        .error-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 60px 40px;
            text-align: center;
            max-width: 500px;
            width: 90%%;
            position: relative;
            overflow: hidden;
        }
        
        .error-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #667eea, #764ba2);
        }
        
        .error-code {
            font-size: 6rem;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        }
        
        .error-title {
            font-size: 2rem;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 16px;
        }
        
        .error-description {
            font-size: 1.1rem;
            color: #718096;
            line-height: 1.6;
            margin-bottom: 40px;
        }
        
        .back-button {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            text-decoration: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        
        .back-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);
        }
        
        .error-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            background: #f7fafc;
            border-radius: 50%%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
        }
        
        @media (max-width: 768px) {
            .error-container {
                padding: 40px 20px;
            }
            
            .error-code {
                font-size: 4rem;
            }
            
            .error-title {
                font-size: 1.5rem;
            }
            
            .error-description {
                font-size: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">
            %s
        </div>
        <div class="error-code">%d</div>
        <h1 class="error-title">%s</h1>
        <p class="error-description">%s</p>
        <a href="javascript:history.back()" class="back-button">Go Back</a>
    </div>
</body>
</html>`, title, getErrorIcon(statusCode), statusCode, message, description)

	contentLength := len(htmlContent)

	// Build the response with basic headers
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, getStatusText(statusCode))
	response += "Content-Type: text/html; charset=utf-8\r\n"
	response += fmt.Sprintf("Content-Length: %d\r\n", contentLength)

	// Add custom headers from plugins
	if customHeaders != nil {
		for key, value := range customHeaders {
			response += fmt.Sprintf("%s: %s\r\n", key, value)
		}
	}

	response += "\r\n" + htmlContent

	return response
}

// getErrorIcon returns an appropriate emoji icon for the error code
func getErrorIcon(statusCode int) string {
	switch statusCode {
	case 400:
		return "⚠️"
	case 401:
		return "🔐"
	case 403:
		return "🚫"
	case 404:
		return "🔍"
	case 429:
		return "⏱️"
	case 500:
		return "⚙️"
	case 502:
		return "🔌"
	case 503:
		return "🚧"
	default:
		return "❌"
	}
}

// getStatusText returns the standard HTTP status text for a given status code
func getStatusText(statusCode int) string {
	switch statusCode {
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Forbidden"
	}
}

// getClientIP extracts the client IP address from the connection
func getClientIP(conn net.Conn) string {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if addr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP.String()
		}
	}
	return "unknown"
}

func main() {
	// Get port from environment or use default
	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = "8080"
	}

	// Validate port
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatal("Invalid port number")
	}

	addr := ":" + port

	// Create and start proxy server
	proxy := NewProxyServer(addr)

	// Get sidra-api URL for logging
	sidraAPI := os.Getenv("SIDRA_API")
	if sidraAPI == "" {
		sidraAPI = "http://localhost:8081"
	}

	log.Printf("Starting Fast HTTP Proxy on port %s", port)
	log.Printf("Configuration scheduler started - fetching from %s/config every 15 seconds", sidraAPI)
	log.Printf("Usage: curl -x http://localhost:%s http://example.com", port)

	// Start a goroutine to log configuration periodically
	go func() {
		time.Sleep(5 * time.Second)                // Wait for initial config fetch
		ticker := time.NewTicker(30 * time.Second) // Log config every 30 seconds
		defer ticker.Stop()

		for range ticker.C {
			proxy.logCurrentConfig()
		}
	}()

	if err := proxy.Start(); err != nil {
		log.Fatal(err)
	}
}
