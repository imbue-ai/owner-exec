// Package config loads the owner-exec daemon configuration from a TOML file
// with flag overrides, and resolves the derived values (signing key, host id
// audience, share-derived resolvers) the server needs.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Role selects which of the two deployments this process is.
type Role string

const (
	// RoleInner runs inside the workspace container (audience ct:<host-id>,
	// grants served, audience/chrome-origin read from share.env).
	RoleInner Role = "inner"
	// RoleVM runs on the remote outer host as root (audience vm:<host-id>,
	// grants disabled, audience is a fixed VM-owned value).
	RoleVM Role = "vm"
)

// File is the on-disk TOML config.
type File struct {
	Role Role `toml:"role"`
	// Audience is the exact audience string this endpoint binds to
	// (e.g. "vm:host-<hex>"). For the inner role it may be empty and derived
	// from share.env instead (share domain), preserving today's behavior; the
	// vm role must set it explicitly.
	Audience string `toml:"audience"`
	// HostID, when set with an empty Audience, forms "ct:<host-id>" /
	// "vm:<host-id>" per role -- the host-id-scoped audience.
	HostID string `toml:"host_id"`
	// ListenHost / ListenPort is where the daemon binds.
	ListenHost string `toml:"listen_host"`
	ListenPort int    `toml:"listen_port"`
	// AuthorizedKeysPath is the authorized_keys file to verify against.
	AuthorizedKeysPath string `toml:"authorized_keys_path"`
	// HostKeyPath is the SSH host private key used to sign responses.
	HostKeyPath string `toml:"host_key_path"`
	// RepoRoot anchors relative file paths and the default cwd.
	RepoRoot string `toml:"repo_root"`
	// GrantsEnabled turns on the /grants endpoints (inner role only).
	GrantsEnabled bool `toml:"grants_enabled"`
	// ShareEnvPath is read for the chrome origin (and, for inner, the share
	// domain audience) so a re-share needs no restart. Empty disables both.
	ShareEnvPath string `toml:"share_env_path"`
	// RegisterPort, when true (inner role), registers the listen port into
	// apps.toml at startup via forward_port.py.
	RegisterPort bool `toml:"register_port"`
	// ServiceName is the apps.toml service name to register under.
	ServiceName string `toml:"service_name"`
	// ForwardPortScript is the path to forward_port.py.
	ForwardPortScript string `toml:"forward_port_script"`
}

// Load reads a TOML config file, applying defaults.
func Load(path string) (*File, error) {
	file := &File{
		ListenHost:         "127.0.0.1",
		AuthorizedKeysPath: expandHome("~/.ssh/authorized_keys"),
		HostKeyPath:        "/etc/ssh/ssh_host_ed25519_key",
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := toml.Unmarshal(raw, file); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := file.validate(); err != nil {
		return nil, err
	}
	file.AuthorizedKeysPath = expandHome(file.AuthorizedKeysPath)
	file.HostKeyPath = expandHome(file.HostKeyPath)
	return file, nil
}

func (f *File) validate() error {
	switch f.Role {
	case RoleInner, RoleVM:
	default:
		return fmt.Errorf("role must be %q or %q, got %q", RoleInner, RoleVM, f.Role)
	}
	if f.ListenPort == 0 {
		return fmt.Errorf("listen_port must be set")
	}
	if f.RepoRoot == "" {
		return fmt.Errorf("repo_root must be set")
	}
	if f.Role == RoleVM && f.ResolvedFixedAudience() == "" {
		return fmt.Errorf("the vm role requires an audience or host_id")
	}
	return nil
}

// ResolvedFixedAudience returns the audience configured directly, or derived
// from host_id + role, or "" when neither is set (inner role then derives it
// from share.env).
func (f *File) ResolvedFixedAudience() string {
	if f.Audience != "" {
		return f.Audience
	}
	if f.HostID == "" {
		return ""
	}
	prefix := "ct:"
	if f.Role == RoleVM {
		prefix = "vm:"
	}
	return prefix + f.HostID
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return home + path[1:]
		}
	}
	return path
}
