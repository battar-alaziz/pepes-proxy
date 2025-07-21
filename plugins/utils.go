package plugins

import "strings"

// parseEnvs parses environment variables string into a map
func parseEnvs(envsStr string) map[string]string {
	result := make(map[string]string)
	if envsStr == "" {
		return result
	}

	pairs := strings.Split(envsStr, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return result
}
