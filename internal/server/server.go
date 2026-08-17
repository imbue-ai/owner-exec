// Package server implements the owner-exec HTTP surface: run a command, read a
// file, write a file, and (inner role only) read/replace the sharing grants
// document. Every request is verified against the strict RFC 9421 profile
// (see internal/profile), and every response is signed with the endpoint's
// SSH host key, bound to the request.
package server

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/imbue-ai/owner-exec/internal/profile"
)

const (
	defaultCommandTimeoutSeconds = 600.0
	maxCommandTimeoutSeconds     = 3600.0
	// Cap request bodies so a hostile caller cannot exhaust memory before the
	// signature is even checked. Generous enough for a base64 file write.
	maxRequestBodyBytes  = 64 * 1024 * 1024
	grantsRelativePath   = "data/.secrets/share_grants.toml"
	absentGrantsRevision = ""
)

// Config is everything the server needs, resolved once at startup. The
// resolver fields are read per request so enabling/disabling sharing (or
// rotating the host key) needs no restart.
type Config struct {
	// AcceptedAudiencesResolver returns the audiences this endpoint answers to
	// (read per request so a re-share is picked up without a restart). An empty
	// return disables exec. The inner role returns its fixed container:<host-id>
	// audience plus the current share domain; the vm role returns only
	// vm:<host-id>.
	AcceptedAudiencesResolver func() []string
	// AuthorizedKeysPath is the authorized_keys file to verify against.
	AuthorizedKeysPath string
	// RepoRoot anchors relative file paths and the default cwd.
	RepoRoot string
	// HostSigningKey / HostKeyID sign responses (the endpoint's SSH host key).
	HostSigningKey ed25519.PrivateKey
	HostKeyID      string
	// GrantsEnabled turns the /grants endpoints on (inner role only).
	GrantsEnabled bool
	// ChromeOriginResolver returns the hosted chrome origin allowed to call
	// cross-origin; "" disables the CORS headers.
	ChromeOriginResolver func() string
	// Version is reported by /_alive.
	Version string
	// Role is "inner" or "vm"; reported by /_alive.
	Role string
	// Now supplies the server clock (injectable for tests).
	Now func() time.Time

	nonces        *profile.NonceCache
	grantsWriteMu sync.Mutex
}

// New returns a ready-to-serve handler for cfg.
func New(cfg *Config) http.Handler {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.nonces = profile.NewNonceCache(profile.CreatedWindowSeconds)
	mux := http.NewServeMux()
	mux.HandleFunc("/_alive", cfg.handleAlive)
	mux.HandleFunc("/run", cfg.wrap(cfg.handleRun))
	mux.HandleFunc("/read-file", cfg.wrap(cfg.handleReadFile))
	mux.HandleFunc("/write-file", cfg.wrap(cfg.handleWriteFile))
	mux.HandleFunc("/grants", cfg.wrap(cfg.handleGrants))
	return cfg.withCORS(mux)
}

// withCORS echoes the configured chrome origin (credentialed, never a
// wildcard) and answers preflights.
func (c *Config) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chromeOrigin := c.ChromeOriginResolver()
		if chromeOrigin != "" && r.Header.Get("Origin") == chromeOrigin {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", chromeOrigin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
			h.Set("Access-Control-Allow-Headers",
				"Content-Type, Signature, Signature-Input, Content-Digest, X-Exec-Audience, X-Exec-Public-Key")
			h.Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Config) handleAlive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"role":    c.Role,
		"version": c.Version,
	})
}

// authedRequest carries the verified request and its exact body to a handler.
type authedRequest struct {
	req  *http.Request
	body []byte
}

// handlerFunc is a verified-request handler. It returns a signed response via
// the helpers below.
type handlerFunc func(w http.ResponseWriter, ar *authedRequest)

// wrap reads and size-limits the body, verifies the envelope, and dispatches.
func (c *Config) wrap(next handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
		if err != nil {
			c.signedError(w, r, nil, http.StatusBadRequest, "could not read request body")
			return
		}
		if len(body) > maxRequestBodyBytes {
			c.signedError(w, r, nil, http.StatusRequestEntityTooLarge, "request body is too large")
			return
		}
		authorizedText, err := os.ReadFile(c.AuthorizedKeysPath)
		if err != nil {
			c.signedError(w, r, body, http.StatusUnauthorized, "could not read authorized_keys")
			return
		}
		verifyErr := profile.VerifyRequest(r, body, profile.RequestVerifyConfig{
			AcceptedAudiences: c.AcceptedAudiencesResolver(),
			AuthorizedKeys:    profile.ParseAuthorizedEd25519Keys(string(authorizedText)),
			Nonces:            c.nonces,
			Now:               c.Now,
		})
		if verifyErr != nil {
			var authErr *profile.AuthError
			if errors.As(verifyErr, &authErr) {
				c.signedError(w, r, body, http.StatusUnauthorized, authErr.Reason)
			} else {
				c.signedError(w, r, body, http.StatusUnauthorized, "unauthorized")
			}
			return
		}
		next(w, &authedRequest{req: r, body: body})
	}
}

// ---------------------------------------------------------------------------
// /run
// ---------------------------------------------------------------------------

type runRequest struct {
	Command        []string `json:"command"`
	Cwd            string   `json:"cwd"`
	TimeoutSeconds *float64 `json:"timeout_seconds"`
}

func (c *Config) handleRun(w http.ResponseWriter, ar *authedRequest) {
	if ar.req.Method != http.MethodPost {
		c.signedError(w, ar.req, ar.body, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload runRequest
	if err := json.Unmarshal(ar.body, &payload); err != nil {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if len(payload.Command) == 0 {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "command must be a non-empty list of strings")
		return
	}
	requestSignature, err := profile.ExtractRequestSignature(ar.req.Header)
	if err != nil {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "could not read request signature")
		return
	}
	cwd := c.resolvePath(payload.Cwd)
	if payload.Cwd == "" {
		cwd = c.RepoRoot
	}
	timeout := resolveTimeout(payload.TimeoutSeconds)

	// The stream is NDJSON; a signed trailer over the exact emitted bytes is
	// the last event. The client treats output as unverified until it checks.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	hasher := sha256.New()
	emit := func(event map[string]any) {
		line, _ := json.Marshal(event)
		line = append(line, '\n')
		hasher.Write(line)
		w.Write(line)
		if flusher != nil {
			flusher.Flush()
		}
	}
	c.streamCommand(payload.Command, cwd, timeout, emit)
	created := c.Now().Unix()
	streamDigest := hasher.Sum(nil)
	signature := profile.SignStreamTrailer(streamDigest, requestSignature, created, c.HostSigningKey, c.HostKeyID)
	trailer := map[string]any{
		"type":      "signature",
		"created":   created,
		"keyid":     c.HostKeyID,
		"tag":       profile.StreamTag,
		"signature": signature,
	}
	// The trailer itself is not folded into the running hash it signs.
	line, _ := json.Marshal(trailer)
	line = append(line, '\n')
	w.Write(line)
	if flusher != nil {
		flusher.Flush()
	}
}

func (c *Config) streamCommand(command []string, cwd string, timeout time.Duration, emit func(map[string]any)) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		emit(map[string]any{"type": "exit", "code": nil, "error": err.Error()})
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		emit(map[string]any{"type": "exit", "code": nil, "error": err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		emit(map[string]any{"type": "exit", "code": nil, "error": err.Error()})
		return
	}

	var wg sync.WaitGroup
	var emitMu sync.Mutex
	pump := func(reader io.Reader, streamName string) {
		defer wg.Done()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			emitMu.Lock()
			emit(map[string]any{"type": streamName, "data": scanner.Text() + "\n"})
			emitMu.Unlock()
		}
	}
	wg.Add(2)
	go pump(stdout, "stdout")
	go pump(stderr, "stderr")

	done := make(chan error, 1)
	go func() {
		wg.Wait()
		done <- cmd.Wait()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case waitErr := <-done:
		exitCode := 0
		if waitErr != nil {
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
		emit(map[string]any{"type": "exit", "code": exitCode})
	case <-timer.C:
		// Kill the whole process group so children die with the parent.
		if cmd.Process != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		emit(map[string]any{"type": "exit", "code": nil, "timed_out": true})
	}
}

// ---------------------------------------------------------------------------
// /read-file, /write-file
// ---------------------------------------------------------------------------

type readFileRequest struct {
	Path string `json:"path"`
}

func (c *Config) handleReadFile(w http.ResponseWriter, ar *authedRequest) {
	var payload readFileRequest
	if err := json.Unmarshal(ar.body, &payload); err != nil || payload.Path == "" {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "path must be a non-empty string")
		return
	}
	target := c.resolvePath(payload.Path)
	content, err := os.ReadFile(target)
	if errors.Is(err, os.ErrNotExist) {
		c.signedResponse(w, ar.req, http.StatusNotFound, map[string]any{"exists": false})
		return
	}
	if err != nil {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, fmt.Sprintf("could not read %s", payload.Path))
		return
	}
	c.signedResponse(w, ar.req, http.StatusOK, map[string]any{
		"exists":      true,
		"content_b64": base64.StdEncoding.EncodeToString(content),
	})
}

type writeFileRequest struct {
	Path       string `json:"path"`
	ContentB64 string `json:"content_b64"`
	Mode       string `json:"mode"`
}

func (c *Config) handleWriteFile(w http.ResponseWriter, ar *authedRequest) {
	var payload writeFileRequest
	if err := json.Unmarshal(ar.body, &payload); err != nil || payload.Path == "" {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "path must be a non-empty string")
		return
	}
	content, err := base64.StdEncoding.DecodeString(payload.ContentB64)
	if err != nil {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "content_b64 is not valid base64")
		return
	}
	mode := resolveMode(payload.Mode)
	target := c.resolvePath(payload.Path)
	if err := atomicWrite(target, content, mode); err != nil {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, fmt.Sprintf("could not write %s", payload.Path))
		return
	}
	c.signedResponse(w, ar.req, http.StatusOK, map[string]any{"written": true})
}

// ---------------------------------------------------------------------------
// /grants (inner role only)
// ---------------------------------------------------------------------------

type putGrantsRequest struct {
	GrantsToml   string  `json:"grants_toml"`
	BaseRevision *string `json:"base_revision"`
}

func (c *Config) handleGrants(w http.ResponseWriter, ar *authedRequest) {
	if !c.GrantsEnabled {
		c.signedError(w, ar.req, ar.body, http.StatusNotFound, "grants are not served by this endpoint")
		return
	}
	switch ar.req.Method {
	case http.MethodGet:
		c.getGrants(w, ar)
	case http.MethodPut:
		c.putGrants(w, ar)
	default:
		c.signedError(w, ar.req, ar.body, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (c *Config) getGrants(w http.ResponseWriter, ar *authedRequest) {
	path := filepath.Join(c.RepoRoot, grantsRelativePath)
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		c.signedResponse(w, ar.req, http.StatusOK, map[string]any{"grants_toml": "", "revision": absentGrantsRevision})
		return
	}
	if err != nil {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "could not read grants")
		return
	}
	c.signedResponse(w, ar.req, http.StatusOK, map[string]any{
		"grants_toml": string(content),
		"revision":    grantsRevision(content),
	})
}

func (c *Config) putGrants(w http.ResponseWriter, ar *authedRequest) {
	var payload putGrantsRequest
	if err := json.Unmarshal(ar.body, &payload); err != nil {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "grants_toml must be a string")
		return
	}
	if !validTOML(payload.GrantsToml) {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "grants_toml is not valid TOML")
		return
	}
	path := filepath.Join(c.RepoRoot, grantsRelativePath)
	newContent := []byte(payload.GrantsToml)

	c.grantsWriteMu.Lock()
	defer c.grantsWriteMu.Unlock()
	current, err := os.ReadFile(path)
	currentRevision := absentGrantsRevision
	switch {
	case errors.Is(err, os.ErrNotExist):
		current = nil
	case err != nil:
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "could not read grants")
		return
	default:
		currentRevision = grantsRevision(current)
	}
	if payload.BaseRevision != nil && *payload.BaseRevision != currentRevision {
		currentToml := ""
		if current != nil {
			currentToml = string(current)
		}
		c.signedResponse(w, ar.req, http.StatusConflict, map[string]any{
			"error":       "grants document changed since base_revision was read",
			"revision":    currentRevision,
			"grants_toml": currentToml,
		})
		return
	}
	if err := atomicWrite(path, newContent, 0o600); err != nil {
		c.signedError(w, ar.req, ar.body, http.StatusBadRequest, "could not write grants")
		return
	}
	c.signedResponse(w, ar.req, http.StatusOK, map[string]any{
		"written":  true,
		"revision": grantsRevision(newContent),
	})
}

// ---------------------------------------------------------------------------
// Signed response helpers
// ---------------------------------------------------------------------------

func (c *Config) signedResponse(w http.ResponseWriter, req *http.Request, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error": "could not serialize response"}`)
		status = http.StatusInternalServerError
	}
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set(profile.ContentDigestHeader, profile.ContentDigest(body))
	signatureInput, signature, err := profile.SignResponse(status, header, req, c.HostSigningKey, c.HostKeyID)
	if err == nil {
		header.Set("Signature-Input", signatureInput)
		header.Set("Signature", signature)
	}
	w.WriteHeader(status)
	w.Write(body)
}

func (c *Config) signedError(w http.ResponseWriter, req *http.Request, _ []byte, status int, message string) {
	c.signedResponse(w, req, status, map[string]any{"error": message})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (c *Config) resolvePath(raw string) string {
	if raw == "" {
		return c.RepoRoot
	}
	if filepath.IsAbs(raw) {
		return raw
	}
	return filepath.Join(c.RepoRoot, raw)
}

func resolveTimeout(raw *float64) time.Duration {
	seconds := defaultCommandTimeoutSeconds
	if raw != nil {
		seconds = *raw
	}
	if seconds < 1 {
		seconds = 1
	}
	if seconds > maxCommandTimeoutSeconds {
		seconds = maxCommandTimeoutSeconds
	}
	return time.Duration(seconds * float64(time.Second))
}

func resolveMode(raw string) os.FileMode {
	if raw == "" {
		return 0o600
	}
	parsed, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0o600
	}
	return os.FileMode(parsed)
}

func atomicWrite(target string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func grantsRevision(content []byte) string {
	digest := sha256.Sum256(content)
	return fmt.Sprintf("%x", digest)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(payload)
	w.Write(body)
}
