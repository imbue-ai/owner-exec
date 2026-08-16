package config

import (
	"os"
	"strings"
)

const (
	shareWorkspaceDomainKey = "SHARE_WORKSPACE_DOMAIN"
	shareChromeOriginKey    = "SHARE_CHROME_ORIGIN"
)

// ReadShareEnvValue reads one exported value from a share.env file, or ""
// when the file is absent/unreadable or the key is missing.
func ReadShareEnvValue(shareEnvPath, wantedKey string) string {
	if shareEnvPath == "" {
		return ""
	}
	raw, err := os.ReadFile(shareEnvPath)
	if err != nil {
		return ""
	}
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "export ") {
			continue
		}
		assignment := strings.TrimPrefix(line, "export ")
		key, value, found := strings.Cut(assignment, "=")
		if found && strings.TrimSpace(key) == wantedKey {
			return strings.Trim(strings.TrimSpace(value), "\"'")
		}
	}
	return ""
}

// ShareDomainAudience reads the workspace's share domain from share.env,
// lowercased (the inner role's default audience when no fixed one is set).
func ShareDomainAudience(shareEnvPath string) string {
	return strings.ToLower(ReadShareEnvValue(shareEnvPath, shareWorkspaceDomainKey))
}

// ShareChromeOrigin reads the hosted chrome origin from share.env, trailing
// slash trimmed, or "" when none is configured.
func ShareChromeOrigin(shareEnvPath string) string {
	return strings.TrimRight(ReadShareEnvValue(shareEnvPath, shareChromeOriginKey), "/")
}
