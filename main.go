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
		sidraAPI = "http://localhost:8081"
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
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Send success response to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// Start bidirectional tunneling
	ps.tunnel(clientConn, targetConn)
}

// executePlugins executes plugins for a given route and returns true if all plugins succeed
func (ps *ProxyServer) executePlugins(route Route, originalReq *fasthttp.Request, clientIP string) (bool, map[string]string, error) {
	// Check if we have plugins_data
	if len(route.PluginsData) == 0 {
		return true, nil, nil // No plugins configured, continue
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
			return false, nil, result.Error
		}

		// Merge headers from plugin
		for key, value := range result.Headers {
			pluginHeaders[key] = value
		}

		log.Printf("Plugin %s executed successfully", pluginData.NamePlugin)
	}

	return true, pluginHeaders, nil
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
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
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
		clientConn.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return
	}

	log.Printf("Found route: upstream=%s, plugins=%d", route.Upstream, len(route.PluginsData))

	// Execute plugins if configured
	if len(route.PluginsData) > 0 {
		pluginSuccess, pluginHeaders, err := ps.executePlugins(route, req, getClientIP(clientConn))
		if err != nil {
			log.Printf("Error executing plugins: %v", err)
			clientConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
			return
		}

		if !pluginSuccess {
			log.Printf("Plugin execution failed, stopping request")
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
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
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
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
		clientConn.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return
	}

	log.Printf("Found route: upstream=%s, plugins=%d", route.Upstream, len(route.PluginsData))

	// Get client IP
	clientIP := getClientIP(clientConn)

	// Execute plugins if configured
	if len(route.PluginsData) > 0 {
		pluginSuccess, pluginHeaders, err := ps.executePlugins(route, req, clientIP)
		if err != nil {
			log.Printf("Error executing plugins: %v", err)
			clientConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
			return
		}

		if !pluginSuccess {
			log.Printf("Plugin execution failed, stopping request")
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
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
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
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
