package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadVMRoleDerivesAudienceFromHostID(t *testing.T) {
	path := writeConfig(t, `
role = "vm"
host_id = "host-abcd1234"
listen_port = 8794
repo_root = "/home/user/workspace"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolvedFixedAudience(); got != "vm:host-abcd1234" {
		t.Fatalf("expected vm:host-abcd1234, got %q", got)
	}
}

func TestLoadInnerRoleDerivesCtAudience(t *testing.T) {
	path := writeConfig(t, `
role = "inner"
host_id = "host-abcd1234"
listen_port = 8793
repo_root = "/home/user/workspace"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolvedFixedAudience(); got != "container:host-abcd1234" {
		t.Fatalf("expected container:host-abcd1234, got %q", got)
	}
}

func TestLoadVMRoleRequiresAudience(t *testing.T) {
	path := writeConfig(t, `
role = "vm"
listen_port = 8794
repo_root = "/home/user/workspace"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error when the vm role has no audience or host_id")
	}
}

func TestLoadRejectsUnknownRole(t *testing.T) {
	path := writeConfig(t, `
role = "sidecar"
listen_port = 8794
repo_root = "/x"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown role")
	}
}

func TestReadShareEnvValue(t *testing.T) {
	dir := t.TempDir()
	shareEnv := filepath.Join(dir, "share.env")
	os.WriteFile(shareEnv, []byte(
		"export SHARE_WORKSPACE_DOMAIN=\"WS.example.com\"\n"+
			"export SHARE_CHROME_ORIGIN='https://chrome.example/'\n"), 0o600)

	if got := ShareDomainAudience(shareEnv); got != "ws.example.com" {
		t.Fatalf("expected lowercased domain, got %q", got)
	}
	if got := ShareChromeOrigin(shareEnv); got != "https://chrome.example" {
		t.Fatalf("expected trailing slash trimmed, got %q", got)
	}
	if got := ShareChromeOrigin(filepath.Join(dir, "missing.env")); got != "" {
		t.Fatalf("expected empty for a missing file, got %q", got)
	}
}
