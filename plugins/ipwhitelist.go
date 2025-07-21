package plugins

import (
	"fmt"
	"strings"
)

// IPWhitelistPlugin handles IP address whitelisting
type IPWhitelistPlugin struct{}

func (p *IPWhitelistPlugin) Execute(ctx *PluginContext) *PluginResult {
	envs := parseEnvs(ctx.Envs)

	// Get whitelisted IPs from environment
	whitelistStr := envs["whitelist_ips"]
	if whitelistStr == "" {
		return &PluginResult{Success: true} // No whitelist configured, allow all
	}

	whitelist := strings.Split(whitelistStr, ",")
	for i, ip := range whitelist {
		whitelist[i] = strings.TrimSpace(ip)
	}

	// Check if client IP is in whitelist
	clientIP := ctx.ClientIP
	for _, allowedIP := range whitelist {
		if clientIP == allowedIP {
			return &PluginResult{Success: true}
		}
	}

	return &PluginResult{
		Success: false,
		Error:   fmt.Errorf("IP %s not in whitelist", clientIP),
	}
}
