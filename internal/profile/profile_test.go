package profile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var testNow = time.Unix(1755300000, 0)

func pemEncode(block *pem.Block) []byte {
	return pem.EncodeToMemory(block)
}

func makeKeypair(t *testing.T, seedByte byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	line, err := PublicKeyLine(private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return private, line
}

func signedTestRequest(t *testing.T, body []byte, audience string, private ed25519.PrivateKey, publicKeyLine string, nonce string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "http://127.0.0.1:8793/run", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(req, body, audience, private, publicKeyLine, nonce); err != nil {
		t.Fatal(err)
	}
	return req
}

func verifyConfig(publicKeyLine string) RequestVerifyConfig {
	return RequestVerifyConfig{
		Audience:       "vm:host-0123",
		AuthorizedKeys: ParseAuthorizedEd25519Keys(publicKeyLine),
		Nonces:         NewNonceCache(CreatedWindowSeconds),
		Now:            time.Now,
	}
}

func TestSignAndVerifyRequestRoundTrip(t *testing.T) {
	private, line := makeKeypair(t, 1)
	body := []byte(`{"command": ["true"]}`)
	req := signedTestRequest(t, body, "vm:host-0123", private, line, "nonce-0123456789abcdef")
	if err := VerifyRequest(req, body, verifyConfig(line)); err != nil {
		t.Fatalf("expected verification to pass: %v", err)
	}
}

func TestVerifyRequestRejectsWrongAudience(t *testing.T) {
	private, line := makeKeypair(t, 1)
	body := []byte(`{}`)
	req := signedTestRequest(t, body, "ct:host-0123", private, line, "nonce-0123456789abcdef")
	err := VerifyRequest(req, body, verifyConfig(line))
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected an audience error, got: %v", err)
	}
}

func TestVerifyRequestRejectsUnauthorizedKey(t *testing.T) {
	private, line := makeKeypair(t, 1)
	_, otherLine := makeKeypair(t, 2)
	body := []byte(`{}`)
	req := signedTestRequest(t, body, "vm:host-0123", private, line, "nonce-0123456789abcdef")
	cfg := verifyConfig(otherLine)
	err := VerifyRequest(req, body, cfg)
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("expected an authorization error, got: %v", err)
	}
}

func TestVerifyRequestRejectsTamperedBody(t *testing.T) {
	private, line := makeKeypair(t, 1)
	body := []byte(`{"command": ["true"]}`)
	req := signedTestRequest(t, body, "vm:host-0123", private, line, "nonce-0123456789abcdef")
	tampered := []byte(`{"command": ["rm"]}  `)
	err := VerifyRequest(req, tampered, verifyConfig(line))
	if err == nil || !strings.Contains(err.Error(), "Content-Digest") {
		t.Fatalf("expected a digest error, got: %v", err)
	}
}

func TestVerifyRequestRejectsTamperedBodyWithRecomputedDigest(t *testing.T) {
	// An attacker who fixes up Content-Digest to match the tampered body must
	// still fail: the digest header is covered by the signature.
	private, line := makeKeypair(t, 1)
	body := []byte(`{"command": ["true"]}`)
	req := signedTestRequest(t, body, "vm:host-0123", private, line, "nonce-0123456789abcdef")
	tampered := []byte(`{"command": ["rm"]}  `)
	req.Header.Set(ContentDigestHeader, ContentDigest(tampered))
	err := VerifyRequest(req, tampered, verifyConfig(line))
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("expected a signature error, got: %v", err)
	}
}

func TestVerifyRequestRejectsReplayedNonce(t *testing.T) {
	private, line := makeKeypair(t, 1)
	body := []byte(`{}`)
	cfg := verifyConfig(line)
	first := signedTestRequest(t, body, "vm:host-0123", private, line, "nonce-0123456789abcdef")
	if err := VerifyRequest(first, body, cfg); err != nil {
		t.Fatal(err)
	}
	second := signedTestRequest(t, body, "vm:host-0123", private, line, "nonce-0123456789abcdef")
	err := VerifyRequest(second, body, cfg)
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected a replay error, got: %v", err)
	}
}

func TestVerifyRequestRejectsShortNonce(t *testing.T) {
	private, line := makeKeypair(t, 1)
	body := []byte(`{}`)
	req := signedTestRequest(t, body, "vm:host-0123", private, line, "short")
	err := VerifyRequest(req, body, verifyConfig(line))
	if err == nil || !strings.Contains(err.Error(), "nonce is too short") {
		t.Fatalf("expected a nonce-length error, got: %v", err)
	}
}

func TestVerifyRequestRejectsStaleCreated(t *testing.T) {
	private, line := makeKeypair(t, 1)
	body := []byte(`{}`)
	req := signedTestRequest(t, body, "vm:host-0123", private, line, "nonce-0123456789abcdef")
	cfg := verifyConfig(line)
	cfg.Now = func() time.Time { return time.Now().Add(120 * time.Second) }
	err := VerifyRequest(req, body, cfg)
	if err == nil || !strings.Contains(err.Error(), "window") {
		t.Fatalf("expected a created-window error, got: %v", err)
	}
}

func TestVerifyRequestRejectsMissingSignature(t *testing.T) {
	_, line := makeKeypair(t, 1)
	body := []byte(`{}`)
	req, err := http.NewRequest("POST", "http://127.0.0.1:8793/run", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(ContentDigestHeader, ContentDigest(body))
	req.Header.Set(AudienceHeader, "vm:host-0123")
	req.Header.Set(PublicKeyHeader, line)
	verifyErr := VerifyRequest(req, body, verifyConfig(line))
	if verifyErr == nil || !strings.Contains(verifyErr.Error(), "Signature-Input") {
		t.Fatalf("expected a missing-signature error, got: %v", verifyErr)
	}
}

func TestVerifyRequestRejectsNonEd25519Key(t *testing.T) {
	private, line := makeKeypair(t, 1)
	body := []byte(`{}`)
	req := signedTestRequest(t, body, "vm:host-0123", private, line, "nonce-0123456789abcdef")
	req.Header.Set(PublicKeyHeader, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 not-a-real-key")
	err := VerifyRequest(req, body, verifyConfig(line))
	if err == nil || !strings.Contains(err.Error(), "unusable") {
		t.Fatalf("expected an unusable-key error, got: %v", err)
	}
}

func TestParseAuthorizedEd25519KeysSkipsOtherKeyTypes(t *testing.T) {
	_, line := makeKeypair(t, 3)
	text := "# comment\n\n" + line + "\nssh-rsa AAAAB3Nza garbage\nnot a key at all\n"
	keys := ParseAuthorizedEd25519Keys(text)
	if len(keys) != 1 {
		t.Fatalf("expected exactly one usable key, got %d", len(keys))
	}
}

func TestSignAndVerifyResponseRoundTrip(t *testing.T) {
	clientKey, clientLine := makeKeypair(t, 1)
	hostKey, hostLine := makeKeypair(t, 9)
	hostSSHPub, _, err := ParsePublicKeyLine(hostLine)
	if err != nil {
		t.Fatal(err)
	}
	hostKeyID := Fingerprint(hostSSHPub)

	requestBody := []byte(`{"path": "data/x"}`)
	req := signedTestRequest(t, requestBody, "vm:host-0123", clientKey, clientLine, "nonce-0123456789abcdef")

	responseBody := []byte(`{"exists": true, "content_b64": "aGk="}`)
	responseHeader := http.Header{}
	responseHeader.Set("Content-Type", "application/json")
	responseHeader.Set(ContentDigestHeader, ContentDigest(responseBody))
	signatureInput, signature, err := SignResponse(200, responseHeader, req, hostKey, hostKeyID)
	if err != nil {
		t.Fatal(err)
	}
	responseHeader.Set("Signature-Input", signatureInput)
	responseHeader.Set("Signature", signature)

	res := &http.Response{StatusCode: 200, Header: responseHeader, Request: req}
	cfg := ResponseVerifyConfig{
		SigningKey: hostKey.Public().(ed25519.PublicKey),
		KeyID:      hostKeyID,
		Now:        time.Now,
	}
	if err := VerifyResponse(res, req, responseBody, cfg); err != nil {
		t.Fatalf("expected response verification to pass: %v", err)
	}

	// A response replayed against a different request must fail: the request
	// signature is a covered component.
	otherBody := []byte(`{"path": "data/y"}`)
	otherReq := signedTestRequest(t, otherBody, "vm:host-0123", clientKey, clientLine, "nonce-fedcba9876543210")
	otherRes := &http.Response{StatusCode: 200, Header: responseHeader, Request: otherReq}
	if err := VerifyResponse(otherRes, otherReq, responseBody, cfg); err == nil {
		t.Fatal("expected verification to fail for a replayed response")
	}

	// A tampered response body must fail.
	if err := VerifyResponse(res, req, []byte(`{"exists": false}`), cfg); err == nil {
		t.Fatal("expected verification to fail for a tampered response body")
	}

	// A different status code must fail: @status is covered.
	badStatus := &http.Response{StatusCode: 500, Header: responseHeader, Request: req}
	if err := VerifyResponse(badStatus, req, responseBody, cfg); err == nil {
		t.Fatal("expected verification to fail for an altered status code")
	}
}

func TestStreamTrailerRoundTrip(t *testing.T) {
	clientKey, clientLine := makeKeypair(t, 1)
	hostKey, hostLine := makeKeypair(t, 9)
	hostSSHPub, _, err := ParsePublicKeyLine(hostLine)
	if err != nil {
		t.Fatal(err)
	}
	hostKeyID := Fingerprint(hostSSHPub)

	body := []byte(`{"command": ["echo", "hello"]}`)
	req := signedTestRequest(t, body, "vm:host-0123", clientKey, clientLine, "nonce-0123456789abcdef")
	requestSignature, err := ExtractRequestSignature(req.Header)
	if err != nil {
		t.Fatal(err)
	}

	stream := []byte(`{"type": "stdout", "data": "hello\n"}` + "\n" + `{"type": "exit", "code": 0}` + "\n")
	streamDigest := sha256.Sum256(stream)
	created := time.Now().Unix()
	signature := SignStreamTrailer(streamDigest[:], requestSignature, created, hostKey, hostKeyID)

	cfg := ResponseVerifyConfig{
		SigningKey: hostKey.Public().(ed25519.PublicKey),
		KeyID:      hostKeyID,
		Now:        time.Now,
	}
	if err := VerifyStreamTrailer(streamDigest[:], requestSignature, created, signature, cfg); err != nil {
		t.Fatalf("expected trailer verification to pass: %v", err)
	}

	// Tampering with the stream bytes must fail.
	tamperedDigest := sha256.Sum256(append(stream, 'x'))
	if err := VerifyStreamTrailer(tamperedDigest[:], requestSignature, created, signature, cfg); err == nil {
		t.Fatal("expected trailer verification to fail for tampered stream bytes")
	}

	// Binding to a different request must fail.
	if err := VerifyStreamTrailer(streamDigest[:], "AAAA", created, signature, cfg); err == nil {
		t.Fatal("expected trailer verification to fail for a different request signature")
	}
}

func TestLoadSigningKeyRoundTrip(t *testing.T) {
	private, line := makeKeypair(t, 7)
	pemBytes, err := marshalOpenSSHPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	loaded, keyID, err := LoadSigningKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(private) {
		t.Fatal("loaded key does not match the original")
	}
	sshPub, _, err := ParsePublicKeyLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != Fingerprint(sshPub) {
		t.Fatalf("keyid mismatch: %s vs %s", keyID, Fingerprint(sshPub))
	}
}

func marshalOpenSSHPrivateKey(private ed25519.PrivateKey) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return nil, err
	}
	return pemEncode(block), nil
}

func TestNonceCachePrunesOldEntries(t *testing.T) {
	cache := NewNonceCache(60)
	if !cache.Claim("nonce-a", testNow) {
		t.Fatal("first claim should succeed")
	}
	if cache.Claim("nonce-a", testNow.Add(30*time.Second)) {
		t.Fatal("claim within the window should fail")
	}
	if !cache.Claim("nonce-a", testNow.Add(90*time.Second)) {
		t.Fatal("claim after the window should succeed (entry pruned)")
	}
}
