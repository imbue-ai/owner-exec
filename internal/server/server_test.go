package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imbue-ai/owner-exec/internal/profile"
	"golang.org/x/crypto/ssh"
)

type harness struct {
	server     *httptest.Server
	clientKey  ed25519.PrivateKey
	clientLine string
	hostPubKey ed25519.PublicKey
	hostKeyID  string
	repoRoot   string
	audience   string
}

func newHarness(t *testing.T, grantsEnabled bool) *harness {
	t.Helper()
	repoRoot := t.TempDir()

	clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	clientLine, err := profile.PublicKeyLine(clientKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	authorizedKeysPath := filepath.Join(repoRoot, "authorized_keys")
	if err := os.WriteFile(authorizedKeysPath, []byte(clientLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hostKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	hostSSHPub, err := ssh.NewPublicKey(hostKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	hostKeyID := ssh.FingerprintSHA256(hostSSHPub)

	audience := "vm:host-abcd"
	cfg := &Config{
		AudienceResolver:     func() string { return audience },
		AuthorizedKeysPath:   authorizedKeysPath,
		RepoRoot:             repoRoot,
		HostSigningKey:       hostKey,
		HostKeyID:            hostKeyID,
		GrantsEnabled:        grantsEnabled,
		ChromeOriginResolver: func() string { return "https://chrome.example" },
		Version:              "test",
		Role:                 "vm",
		Now:                  time.Now,
	}
	server := httptest.NewServer(New(cfg))
	t.Cleanup(server.Close)
	return &harness{
		server:     server,
		clientKey:  clientKey,
		clientLine: clientLine,
		hostPubKey: hostKey.Public().(ed25519.PublicKey),
		hostKeyID:  hostKeyID,
		repoRoot:   repoRoot,
		audience:   audience,
	}
}

func (h *harness) signedDo(t *testing.T, method, path string, body []byte, nonce string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, h.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.SignRequest(req, body, h.audience, h.clientKey, h.clientLine, nonce); err != nil {
		t.Fatal(err)
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (h *harness) responseVerifyConfig() profile.ResponseVerifyConfig {
	return profile.ResponseVerifyConfig{SigningKey: h.hostPubKey, KeyID: h.hostKeyID, Now: time.Now}
}

func TestWriteThenReadFileRoundTripWithSignedResponses(t *testing.T) {
	h := newHarness(t, false)

	writeBody, _ := json.Marshal(map[string]any{
		"path":        "data/example.txt",
		"content_b64": base64.StdEncoding.EncodeToString([]byte("hello world")),
	})
	// Re-sign into a fresh request so we can verify the response against it.
	writeReq, _ := http.NewRequest("POST", h.server.URL+"/write-file", bytes.NewReader(writeBody))
	if err := profile.SignRequest(writeReq, writeBody, h.audience, h.clientKey, h.clientLine, "nonce-write-000000000"); err != nil {
		t.Fatal(err)
	}
	writeResp, err := h.server.Client().Do(writeReq)
	if err != nil {
		t.Fatal(err)
	}
	writeRespBody, _ := io.ReadAll(writeResp.Body)
	writeResp.Body.Close()
	if writeResp.StatusCode != http.StatusOK {
		t.Fatalf("write-file failed: %d %s", writeResp.StatusCode, writeRespBody)
	}
	if err := profile.VerifyResponse(writeResp, writeReq, writeRespBody, h.responseVerifyConfig()); err != nil {
		t.Fatalf("write-file response signature did not verify: %v", err)
	}

	onDisk, err := os.ReadFile(filepath.Join(h.repoRoot, "data/example.txt"))
	if err != nil || string(onDisk) != "hello world" {
		t.Fatalf("file not written correctly: %q %v", onDisk, err)
	}

	readBody, _ := json.Marshal(map[string]any{"path": "data/example.txt"})
	readReq, _ := http.NewRequest("POST", h.server.URL+"/read-file", bytes.NewReader(readBody))
	if err := profile.SignRequest(readReq, readBody, h.audience, h.clientKey, h.clientLine, "nonce-read-0000000000"); err != nil {
		t.Fatal(err)
	}
	readResp, err := h.server.Client().Do(readReq)
	if err != nil {
		t.Fatal(err)
	}
	readRespBody, _ := io.ReadAll(readResp.Body)
	readResp.Body.Close()
	if err := profile.VerifyResponse(readResp, readReq, readRespBody, h.responseVerifyConfig()); err != nil {
		t.Fatalf("read-file response signature did not verify: %v", err)
	}
	var parsed struct {
		Exists     bool   `json:"exists"`
		ContentB64 string `json:"content_b64"`
	}
	if err := json.Unmarshal(readRespBody, &parsed); err != nil {
		t.Fatal(err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(parsed.ContentB64)
	if !parsed.Exists || string(decoded) != "hello world" {
		t.Fatalf("read-file returned wrong content: %+v", parsed)
	}
}

func TestReadMissingFileReturns404(t *testing.T) {
	h := newHarness(t, false)
	body, _ := json.Marshal(map[string]any{"path": "data/nope.txt"})
	resp := h.signedDo(t, "POST", "/read-file", body, "nonce-missing-00000000")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestUnauthenticatedRequestIsRejected(t *testing.T) {
	h := newHarness(t, false)
	body := []byte(`{"path": "data/x"}`)
	req, _ := http.NewRequest("POST", h.server.URL+"/read-file", bytes.NewReader(body))
	// No signature headers at all.
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestRunStreamsAndSignsTrailer(t *testing.T) {
	h := newHarness(t, false)
	body, _ := json.Marshal(map[string]any{"command": []string{"sh", "-c", "echo out; echo err 1>&2; exit 3"}})
	runReq, _ := http.NewRequest("POST", h.server.URL+"/run", bytes.NewReader(body))
	if err := profile.SignRequest(runReq, body, h.audience, h.clientKey, h.clientLine, "nonce-run-00000000000"); err != nil {
		t.Fatal(err)
	}
	requestSignature, err := profile.ExtractRequestSignature(runReq.Header)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.server.Client().Do(runReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	// Split the trailer (last line) from the signed stream body.
	lines := splitNonEmptyLines(string(raw))
	if len(lines) < 2 {
		t.Fatalf("expected at least output + trailer, got: %q", raw)
	}
	trailerLine := lines[len(lines)-1]
	streamBytes := raw[:len(raw)-len(trailerLine)-1] // drop trailer line + its newline

	var trailer struct {
		Type      string `json:"type"`
		Created   int64  `json:"created"`
		KeyID     string `json:"keyid"`
		Tag       string `json:"tag"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal([]byte(trailerLine), &trailer); err != nil {
		t.Fatalf("trailer is not JSON: %v (%q)", err, trailerLine)
	}
	if trailer.Type != "signature" {
		t.Fatalf("last event is not a signature trailer: %+v", trailer)
	}
	streamDigest := sha256.Sum256(streamBytes)
	if err := profile.VerifyStreamTrailer(streamDigest[:], requestSignature, trailer.Created, trailer.Signature, h.responseVerifyConfig()); err != nil {
		t.Fatalf("stream trailer did not verify: %v", err)
	}

	// Confirm the exit code came through.
	if !strings.Contains(string(streamBytes), `"code":3`) {
		t.Fatalf("expected exit code 3 in stream: %q", streamBytes)
	}
}

func TestRunTimesOutAndKillsProcess(t *testing.T) {
	h := newHarness(t, false)
	timeout := 0.5
	body, _ := json.Marshal(map[string]any{"command": []string{"sleep", "30"}, "timeout_seconds": timeout})
	resp := h.signedDo(t, "POST", "/run", body, "nonce-timeout-00000000")
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), `"timed_out":true`) {
		t.Fatalf("expected a timeout marker in stream: %q", raw)
	}
}

func TestGrantsCASConflict(t *testing.T) {
	h := newHarness(t, true)

	// Seed with base_revision "" (absent).
	putBody, _ := json.Marshal(map[string]any{
		"grants_toml":   "[grants]\nowner = true\n",
		"base_revision": "",
	})
	resp := h.signedDo(t, "PUT", "/grants", putBody, "nonce-put1-0000000000")
	putRespBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial grants put failed: %d %s", resp.StatusCode, putRespBody)
	}
	var putResult struct {
		Revision string `json:"revision"`
	}
	json.Unmarshal(putRespBody, &putResult)

	// A stale base_revision must 409.
	staleBody, _ := json.Marshal(map[string]any{
		"grants_toml":   "[grants]\nowner = false\n",
		"base_revision": "deadbeef",
	})
	conflictResp := h.signedDo(t, "PUT", "/grants", staleBody, "nonce-put2-0000000000")
	conflictRespBody, _ := io.ReadAll(conflictResp.Body)
	conflictResp.Body.Close()
	if conflictResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 on stale revision, got %d", conflictResp.StatusCode)
	}
	if !strings.Contains(string(conflictRespBody), "owner = true") {
		t.Fatalf("conflict should carry the current document: %s", conflictRespBody)
	}

	// The correct base_revision succeeds.
	freshBody, _ := json.Marshal(map[string]any{
		"grants_toml":   "[grants]\nowner = false\n",
		"base_revision": putResult.Revision,
	})
	okResp := h.signedDo(t, "PUT", "/grants", freshBody, "nonce-put3-0000000000")
	okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with the correct base_revision, got %d", okResp.StatusCode)
	}
}

func TestGrantsRejectsInvalidTOML(t *testing.T) {
	h := newHarness(t, true)
	body, _ := json.Marshal(map[string]any{"grants_toml": "this is = = not toml"})
	resp := h.signedDo(t, "PUT", "/grants", body, "nonce-badtoml-00000000")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid TOML, got %d", resp.StatusCode)
	}
}

func TestGrantsDisabledOnVMRole(t *testing.T) {
	h := newHarness(t, false)
	resp := h.signedDo(t, "GET", "/grants", nil, "nonce-nogrants-0000000")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 when grants are disabled, got %d", resp.StatusCode)
	}
}

func TestAliveIsUnauthenticated(t *testing.T) {
	h := newHarness(t, false)
	resp, err := h.server.Client().Get(h.server.URL + "/_alive")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /_alive, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"role":"vm"`) {
		t.Fatalf("expected role in /_alive body: %s", body)
	}
}

func TestCORSPreflight(t *testing.T) {
	h := newHarness(t, false)
	req, _ := http.NewRequest("OPTIONS", h.server.URL+"/run", nil)
	req.Header.Set("Origin", "https://chrome.example")
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for preflight, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://chrome.example" {
		t.Fatalf("expected the chrome origin echoed, got %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func splitNonEmptyLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
