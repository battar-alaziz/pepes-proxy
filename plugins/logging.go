package plugins

import (
	"log"
	"strings"
)

// LoggingPlugin handles request logging
type LoggingPlugin struct{}

func (p *LoggingPlugin) Execute(ctx *PluginContext) *PluginResult {
	envs := parseEnvs(ctx.Envs)

	logLevel := envs["log_level"]
	if logLevel == "" {
		logLevel = "info"
	}

	// Log request details
	log.Printf("[%s] %s %s from %s",
		strings.ToUpper(logLevel),
		ctx.Method,
		ctx.Path,
		ctx.ClientIP,
	)

	// Log headers if debug level
	if logLevel == "debug" {
		for key, value := range ctx.Headers {
			log.Printf("  Header: %s = %s", key, value)
		}
	}

	return &PluginResult{Success: true}
}
