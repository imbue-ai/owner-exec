// Package profile implements the strict RFC 9421 / RFC 9530 signing profile
// used by owner-exec.
//
// Every request is signed with an Ed25519 key whose public half must appear in
// the target's authorized_keys, and every response is signed with the target
// endpoint's SSH host key, bound to the request it answers. The profile pins
// everything the RFC leaves open: exactly one signature (label "sig1"), the
// ed25519 algorithm, a fixed covered-component list, and a fixed parameter
// set. See spec/profile.md for the full contract.
package profile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/yaronf/httpsign"
	"golang.org/x/crypto/ssh"
)

const (
	// SignatureLabel is the single signature label the profile allows.
	SignatureLabel = "sig1"

	// RequestTag, ResponseTag and StreamTag are the domain-separation tags for
	// the three signature kinds. A signature made under one tag can never
	// verify under another.
	RequestTag  = "imbue-owner-exec"
	ResponseTag = "imbue-owner-exec-resp"
	StreamTag   = "imbue-owner-exec-stream"

	// CreatedWindowSeconds bounds |now - created| for request signatures. It
	// also bounds how long a captured envelope stays replayable, together with
	// the nonce cache.
	CreatedWindowSeconds = 60

	// MaxExpiresAfterCreatedSeconds bounds how far past created a signer may
	// place expires, so a signer cannot mint long-lived envelopes.
	MaxExpiresAfterCreatedSeconds = 300

	// ResponseCreatedWindowSeconds bounds |now - created| for response
	// signatures. Responses are consumed immediately and are already bound to
	// their request, so the window is lenient.
	ResponseCreatedWindowSeconds = 300

	// MinNonceLength is the minimum length of the nonce parameter.
	MinNonceLength = 16

	// AudienceHeader carries the audience the envelope binds to; the verifier
	// compares it against its own configured audience, never the request URL.
	AudienceHeader = "X-Exec-Audience"

	// PublicKeyHeader carries the signer's OpenSSH public key line.
	PublicKeyHeader = "X-Exec-Public-Key"

	// ContentDigestHeader is the RFC 9530 body-digest header.
	ContentDigestHeader = "Content-Digest"
)

// AuthError is returned for any envelope that fails verification; servers map
// it to HTTP 401.
type AuthError struct {
	Reason string
}

func (e *AuthError) Error() string {
	return e.Reason
}

func authErrorf(format string, args ...any) error {
	return &AuthError{Reason: fmt.Sprintf(format, args...)}
}

// expectedComponent is one covered component of the strict profile: its name
// plus the exact structured-field parameters it must carry.
type expectedComponent struct {
	name     string
	reqBound bool   // carries the ;req parameter
	dictKey  string // non-empty: carries ;key="<dictKey>"
}

var requestComponents = []expectedComponent{
	{name: "@method"},
	{name: "@path"},
	{name: "content-digest"},
	{name: "x-exec-audience"},
	{name: "x-exec-public-key"},
}

var responseComponents = []expectedComponent{
	{name: "@status"},
	{name: "content-digest"},
	{name: "@method", reqBound: true},
	{name: "@path", reqBound: true},
	{name: "signature", reqBound: true, dictKey: SignatureLabel},
}

// ---------------------------------------------------------------------------
// Content digest (RFC 9530)
// ---------------------------------------------------------------------------

// ContentDigest returns the sha-256 Content-Digest header value for body.
func ContentDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"
}

// ValidateContentDigest checks that headerValue is exactly one sha-256 entry
// matching body.
func ValidateContentDigest(headerValue string, body []byte) error {
	parsed, err := httpsfv.UnmarshalDictionary([]string{headerValue})
	if err != nil {
		return authErrorf("Content-Digest is not a valid structured-field dictionary: %v", err)
	}
	names := parsed.Names()
	if len(names) != 1 || names[0] != "sha-256" {
		return authErrorf("Content-Digest must carry exactly one sha-256 entry")
	}
	member, _ := parsed.Get("sha-256")
	item, ok := member.(httpsfv.Item)
	if !ok {
		return authErrorf("Content-Digest sha-256 entry is not an item")
	}
	received, ok := item.Value.([]byte)
	if !ok {
		return authErrorf("Content-Digest sha-256 entry is not a byte sequence")
	}
	computed := sha256.Sum256(body)
	if !hmacEqual(received, computed[:]) {
		return authErrorf("Content-Digest does not match the request body")
	}
	return nil
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

// ParsePublicKeyLine parses one OpenSSH authorized_keys-style line into its
// SSH form (for fingerprinting) and raw Ed25519 form (for verification).
func ParsePublicKeyLine(line string) (ssh.PublicKey, ed25519.PublicKey, error) {
	sshKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return nil, nil, fmt.Errorf("not a usable OpenSSH public key: %w", err)
	}
	cryptoKey, ok := sshKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key does not expose a crypto key")
	}
	edKey, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key is not Ed25519")
	}
	return sshKey, edKey, nil
}

// Fingerprint returns the standard SHA256 OpenSSH fingerprint used as keyid.
func Fingerprint(pub ssh.PublicKey) string {
	return ssh.FingerprintSHA256(pub)
}

// ParseAuthorizedEd25519Keys loads every Ed25519 key from an authorized_keys
// file body. Non-Ed25519 keys and unparseable lines are skipped: the target
// may also authorize RSA/ECDSA keys for plain SSH, but exec accepts only
// Ed25519.
func ParseAuthorizedEd25519Keys(text string) []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, edKey, err := ParsePublicKeyLine(line)
		if err != nil {
			continue
		}
		keys = append(keys, edKey)
	}
	return keys
}

// IsAuthorized reports whether key is one of the authorized keys, by raw
// public-key bytes.
func IsAuthorized(key ed25519.PublicKey, authorized []ed25519.PublicKey) bool {
	for _, candidate := range authorized {
		if hmacEqual(key, candidate) {
			return true
		}
	}
	return false
}

// LoadSigningKey parses an unencrypted OpenSSH/PEM private key file body into
// an Ed25519 private key plus its keyid fingerprint.
func LoadSigningKey(pemBytes []byte) (ed25519.PrivateKey, string, error) {
	parsed, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, "", fmt.Errorf("cannot parse signing key: %w", err)
	}
	var private ed25519.PrivateKey
	switch key := parsed.(type) {
	case ed25519.PrivateKey:
		private = key
	case *ed25519.PrivateKey:
		private = *key
	default:
		return nil, "", fmt.Errorf("signing key is not Ed25519 (got %T)", parsed)
	}
	sshPub, err := ssh.NewPublicKey(private.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, "", fmt.Errorf("cannot derive public key: %w", err)
	}
	return private, Fingerprint(sshPub), nil
}

// PublicKeyLine renders an Ed25519 public key as an OpenSSH authorized_keys
// line (no comment, no trailing newline).
func PublicKeyLine(pub ed25519.PublicKey) (string, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

// ---------------------------------------------------------------------------
// Nonce cache
// ---------------------------------------------------------------------------

// NonceCache remembers recently seen nonces so a signed envelope cannot be
// replayed. Entries older than the window are pruned on each use, so the
// cache never grows beyond the requests seen within one window.
type NonceCache struct {
	windowSeconds float64
	mu            sync.Mutex
	seenAtByNonce map[string]float64
}

// NewNonceCache returns a cache whose entries expire after windowSeconds.
func NewNonceCache(windowSeconds float64) *NonceCache {
	return &NonceCache{
		windowSeconds: windowSeconds,
		seenAtByNonce: map[string]float64{},
	}
}

// Claim records nonce; it returns false when the nonce was already used
// within the window.
func (c *NonceCache) Claim(nonce string, now time.Time) bool {
	nowSeconds := float64(now.UnixNano()) / 1e9
	c.mu.Lock()
	defer c.mu.Unlock()
	for seen, seenAt := range c.seenAtByNonce {
		if nowSeconds-seenAt >= c.windowSeconds {
			delete(c.seenAtByNonce, seen)
		}
	}
	if _, ok := c.seenAtByNonce[nonce]; ok {
		return false
	}
	c.seenAtByNonce[nonce] = nowSeconds
	return true
}

// ---------------------------------------------------------------------------
// Strict Signature-Input parsing
// ---------------------------------------------------------------------------

// signatureParams is the parsed parameter set of a sig1 signature member.
type signatureParams struct {
	created int64
	expires int64 // 0 when absent
	keyID   string
	nonce   string // "" when absent
	tag     string
}

// parseStrictSignatureInput parses a Signature-Input header and enforces the
// profile: exactly one member named sig1, the exact covered-component list,
// and the exact parameter set (requireNonceAndExpires selects the request vs
// response profile). alg, when present, must be "ed25519".
func parseStrictSignatureInput(
	headerValue string,
	components []expectedComponent,
	requireNonceAndExpires bool,
) (*signatureParams, error) {
	dict, err := httpsfv.UnmarshalDictionary([]string{headerValue})
	if err != nil {
		return nil, authErrorf("Signature-Input is not a valid structured-field dictionary: %v", err)
	}
	names := dict.Names()
	if len(names) != 1 || names[0] != SignatureLabel {
		return nil, authErrorf("Signature-Input must carry exactly one %q signature", SignatureLabel)
	}
	member, _ := dict.Get(SignatureLabel)
	innerList, ok := member.(httpsfv.InnerList)
	if !ok {
		return nil, authErrorf("Signature-Input %q member is not an inner list", SignatureLabel)
	}

	if err := matchComponents(innerList.Items, components); err != nil {
		return nil, err
	}

	// Enforce the exact parameter set.
	allowed := map[string]bool{"created": true, "keyid": true, "tag": true, "alg": true}
	if requireNonceAndExpires {
		allowed["expires"] = true
		allowed["nonce"] = true
	}
	for _, name := range innerList.Params.Names() {
		if !allowed[name] {
			return nil, authErrorf("signature parameter %q is not allowed by the profile", name)
		}
	}
	params := &signatureParams{}
	created, ok := paramInt(innerList.Params, "created")
	if !ok {
		return nil, authErrorf("signature is missing the created parameter")
	}
	params.created = created
	keyID, ok := paramString(innerList.Params, "keyid")
	if !ok {
		return nil, authErrorf("signature is missing the keyid parameter")
	}
	params.keyID = keyID
	tag, ok := paramString(innerList.Params, "tag")
	if !ok {
		return nil, authErrorf("signature is missing the tag parameter")
	}
	params.tag = tag
	if alg, present := paramString(innerList.Params, "alg"); present && alg != "ed25519" {
		return nil, authErrorf("signature alg must be ed25519 when present")
	}
	if requireNonceAndExpires {
		expires, ok := paramInt(innerList.Params, "expires")
		if !ok {
			return nil, authErrorf("signature is missing the expires parameter")
		}
		params.expires = expires
		nonce, ok := paramString(innerList.Params, "nonce")
		if !ok {
			return nil, authErrorf("signature is missing the nonce parameter")
		}
		params.nonce = nonce
	}
	return params, nil
}

// SignatureCreated extracts the created parameter from a sig1 Signature-Input
// header value. It is used by the vector generator to record the clock at
// which a static vector verifies.
func SignatureCreated(signatureInputHeader string) (int64, error) {
	dict, err := httpsfv.UnmarshalDictionary([]string{signatureInputHeader})
	if err != nil {
		return 0, fmt.Errorf("Signature-Input is not a valid dictionary: %w", err)
	}
	member, ok := dict.Get(SignatureLabel)
	if !ok {
		return 0, fmt.Errorf("Signature-Input has no %q member", SignatureLabel)
	}
	innerList, ok := member.(httpsfv.InnerList)
	if !ok {
		return 0, fmt.Errorf("Signature-Input %q member is not an inner list", SignatureLabel)
	}
	created, ok := paramInt(innerList.Params, "created")
	if !ok {
		return 0, fmt.Errorf("Signature-Input is missing the created parameter")
	}
	return created, nil
}

func paramString(params *httpsfv.Params, name string) (string, bool) {
	raw, ok := params.Get(name)
	if !ok {
		return "", false
	}
	value, ok := raw.(string)
	return value, ok
}

func paramInt(params *httpsfv.Params, name string) (int64, bool) {
	raw, ok := params.Get(name)
	if !ok {
		return 0, false
	}
	value, ok := raw.(int64)
	return value, ok
}

// matchComponents structurally compares the covered components against the
// expected list: same names, same order, same per-component parameters.
func matchComponents(items []httpsfv.Item, expected []expectedComponent) error {
	if len(items) != len(expected) {
		return authErrorf("signature covers %d components, profile requires %d", len(items), len(expected))
	}
	for idx, item := range items {
		want := expected[idx]
		name, ok := item.Value.(string)
		if !ok || name != want.name {
			return authErrorf("covered component %d must be %q", idx, want.name)
		}
		wantParamCount := 0
		if want.reqBound {
			wantParamCount++
			raw, present := item.Params.Get("req")
			isReq, isBool := raw.(bool)
			if !present || !isBool || !isReq {
				return authErrorf("covered component %q must carry the req parameter", want.name)
			}
		}
		if want.dictKey != "" {
			wantParamCount++
			raw, present := item.Params.Get("key")
			key, isString := raw.(string)
			if !present || !isString || key != want.dictKey {
				return authErrorf("covered component %q must carry key=%q", want.name, want.dictKey)
			}
		}
		if len(item.Params.Names()) != wantParamCount {
			return authErrorf("covered component %q carries unexpected parameters", want.name)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Request signing and verification
// ---------------------------------------------------------------------------

var requestFields = httpsign.Headers(
	"@method", "@path", "content-digest", "x-exec-audience", "x-exec-public-key")

// SignRequest signs req in place per the request profile: it sets the
// Content-Digest, X-Exec-Audience and X-Exec-Public-Key headers, then the
// Signature-Input and Signature headers. body must be the exact request body
// bytes (empty slice for body-less requests).
func SignRequest(
	req *http.Request,
	body []byte,
	audience string,
	privateKey ed25519.PrivateKey,
	publicKeyLine string,
	nonce string,
) error {
	sshPub, _, err := ParsePublicKeyLine(publicKeyLine)
	if err != nil {
		return fmt.Errorf("signing public key line: %w", err)
	}
	req.Header.Set(ContentDigestHeader, ContentDigest(body))
	req.Header.Set(AudienceHeader, audience)
	req.Header.Set(PublicKeyHeader, strings.TrimSpace(publicKeyLine))

	config := httpsign.NewSignConfig().
		SignAlg(false).
		SetKeyID(Fingerprint(sshPub)).
		SetNonce(nonce).
		SetTag(RequestTag).
		SetExpiresAfter(CreatedWindowSeconds)
	signer, err := httpsign.NewEd25519Signer(privateKey, config, requestFields)
	if err != nil {
		return fmt.Errorf("building request signer: %w", err)
	}
	signatureInput, signature, err := httpsign.SignRequest(SignatureLabel, *signer, req)
	if err != nil {
		return fmt.Errorf("signing request: %w", err)
	}
	req.Header.Set("Signature-Input", signatureInput)
	req.Header.Set("Signature", signature)
	return nil
}

// RequestVerifyConfig is everything a server needs to verify one request.
type RequestVerifyConfig struct {
	// Audience is the verifier's own audience; the covered X-Exec-Audience
	// header must equal it exactly.
	Audience string
	// AuthorizedKeys is the current set of Ed25519 keys the target trusts.
	AuthorizedKeys []ed25519.PublicKey
	// Nonces is the replay cache; the nonce is claimed only after every other
	// check has passed.
	Nonces *NonceCache
	// Now supplies the verification clock (injectable for tests/vectors).
	Now func() time.Time
}

// VerifyRequest verifies req against the strict request profile, returning an
// *AuthError on any failure. body must be the exact request body bytes; the
// caller is responsible for having limited its size.
func VerifyRequest(req *http.Request, body []byte, cfg RequestVerifyConfig) error {
	if cfg.Audience == "" {
		return authErrorf("no audience is configured, so exec is unavailable")
	}
	audience := req.Header.Get(AudienceHeader)
	if audience == "" {
		return authErrorf("request is missing the %s header", AudienceHeader)
	}
	if audience != cfg.Audience {
		return authErrorf("request audience does not match this endpoint")
	}

	publicKeyLine := req.Header.Get(PublicKeyHeader)
	if publicKeyLine == "" {
		return authErrorf("request is missing the %s header", PublicKeyHeader)
	}
	sshPub, edPub, err := ParsePublicKeyLine(publicKeyLine)
	if err != nil {
		return authErrorf("presented public key is unusable: %v", err)
	}
	if !IsAuthorized(edPub, cfg.AuthorizedKeys) {
		return authErrorf("presented public key is not authorized on this endpoint")
	}

	signatureInput := req.Header.Get("Signature-Input")
	if signatureInput == "" {
		return authErrorf("request is missing the Signature-Input header")
	}
	params, err := parseStrictSignatureInput(signatureInput, requestComponents, true)
	if err != nil {
		return err
	}
	if params.tag != RequestTag {
		return authErrorf("signature tag must be %q", RequestTag)
	}
	if params.keyID != Fingerprint(sshPub) {
		return authErrorf("signature keyid does not match the presented public key")
	}
	if len(params.nonce) < MinNonceLength {
		return authErrorf("signature nonce is too short")
	}

	now := cfg.Now().Unix()
	if params.created > now+CreatedWindowSeconds || params.created < now-CreatedWindowSeconds {
		return authErrorf("signature created timestamp is outside the allowed window")
	}
	if params.expires <= params.created {
		return authErrorf("signature expires must be after created")
	}
	if params.expires > params.created+MaxExpiresAfterCreatedSeconds {
		return authErrorf("signature expires too long after created")
	}
	if now >= params.expires {
		return authErrorf("signature has expired")
	}

	if err := ValidateContentDigest(req.Header.Get(ContentDigestHeader), body); err != nil {
		return err
	}

	verifyConfig := httpsign.NewVerifyConfig().
		SetVerifyCreated(false).
		SetKeyID(params.keyID).
		SetAllowedTags([]string{RequestTag})
	verifier, err := httpsign.NewEd25519Verifier(edPub, verifyConfig, requestFields)
	if err != nil {
		return authErrorf("building verifier: %v", err)
	}
	if err := httpsign.VerifyRequest(SignatureLabel, *verifier, req); err != nil {
		return authErrorf("signature does not verify: %v", err)
	}

	// The nonce is claimed last so a failed request never burns a nonce a
	// legitimate in-flight request is about to use.
	if !cfg.Nonces.Claim(params.nonce, cfg.Now()) {
		return authErrorf("signature nonce was already used (replay)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Response signing and verification
// ---------------------------------------------------------------------------

func responseFields() httpsign.Fields {
	fields := httpsign.NewFields()
	fields.AddHeader("@status")
	fields.AddHeader("content-digest")
	fields.AddHeaderExt("@method", false, false, true, false)
	fields.AddHeaderExt("@path", false, false, true, false)
	fields.AddDictHeaderExt("signature", SignatureLabel, false, true, false)
	return *fields
}

// SignResponse produces the Signature-Input and Signature header values for a
// response, bound to the request it answers. The response's Content-Digest
// header must already be set.
func SignResponse(
	statusCode int,
	responseHeader http.Header,
	req *http.Request,
	signingKey ed25519.PrivateKey,
	keyID string,
) (signatureInput string, signature string, err error) {
	config := httpsign.NewSignConfig().
		SignAlg(false).
		SetKeyID(keyID).
		SetTag(ResponseTag)
	signer, err := httpsign.NewEd25519Signer(signingKey, config, responseFields())
	if err != nil {
		return "", "", fmt.Errorf("building response signer: %w", err)
	}
	response := &http.Response{
		StatusCode: statusCode,
		Header:     responseHeader,
		Request:    req,
	}
	return httpsign.SignResponse(SignatureLabel, *signer, response, req)
}

// ResponseVerifyConfig is everything a client needs to verify one response.
type ResponseVerifyConfig struct {
	// SigningKey is the pinned Ed25519 host key of the endpoint.
	SigningKey ed25519.PublicKey
	// KeyID is the pinned key's SHA256 OpenSSH fingerprint.
	KeyID string
	// Now supplies the verification clock.
	Now func() time.Time
}

// VerifyResponse verifies a signed response against the strict response
// profile. req must be the exact signed request the response answers, and
// body the exact response body bytes.
func VerifyResponse(res *http.Response, req *http.Request, body []byte, cfg ResponseVerifyConfig) error {
	signatureInput := res.Header.Get("Signature-Input")
	if signatureInput == "" {
		return authErrorf("response is missing the Signature-Input header")
	}
	params, err := parseStrictSignatureInput(signatureInput, responseComponents, false)
	if err != nil {
		return err
	}
	if params.tag != ResponseTag {
		return authErrorf("response signature tag must be %q", ResponseTag)
	}
	if params.keyID != cfg.KeyID {
		return authErrorf("response signature keyid does not match the pinned host key")
	}
	now := cfg.Now().Unix()
	if params.created > now+ResponseCreatedWindowSeconds || params.created < now-ResponseCreatedWindowSeconds {
		return authErrorf("response signature created timestamp is outside the allowed window")
	}
	if err := ValidateContentDigest(res.Header.Get(ContentDigestHeader), body); err != nil {
		return err
	}
	verifyConfig := httpsign.NewVerifyConfig().
		SetVerifyCreated(false).
		SetKeyID(cfg.KeyID).
		SetAllowedTags([]string{ResponseTag})
	verifier, err := httpsign.NewEd25519Verifier(cfg.SigningKey, verifyConfig, responseFields())
	if err != nil {
		return authErrorf("building response verifier: %v", err)
	}
	if res.Request == nil {
		res.Request = req
	}
	if err := httpsign.VerifyResponse(SignatureLabel, *verifier, res, req); err != nil {
		return authErrorf("response signature does not verify: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Stream trailer signatures
// ---------------------------------------------------------------------------

// ExtractRequestSignature returns the base64 signature bytes of the request's
// sig1 signature, as carried in its Signature header.
func ExtractRequestSignature(header http.Header) (string, error) {
	value := header.Get("Signature")
	if value == "" {
		return "", authErrorf("request is missing the Signature header")
	}
	dict, err := httpsfv.UnmarshalDictionary([]string{value})
	if err != nil {
		return "", authErrorf("Signature is not a valid structured-field dictionary: %v", err)
	}
	member, ok := dict.Get(SignatureLabel)
	if !ok {
		return "", authErrorf("Signature has no %q member", SignatureLabel)
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return "", authErrorf("Signature %q member is not an item", SignatureLabel)
	}
	raw, ok := item.Value.([]byte)
	if !ok {
		return "", authErrorf("Signature %q member is not a byte sequence", SignatureLabel)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// StreamTrailerBase builds the exact bytes a stream-trailer signature covers.
// RFC 9421 signs complete messages, not streams, so this is the profile's one
// custom construction; it mirrors the RFC's signature-base shape.
func StreamTrailerBase(streamSHA256 []byte, requestSignatureB64 string, keyID string, created int64) []byte {
	lines := []string{
		fmt.Sprintf("\"stream-digest\": sha-256=:%s:", base64.StdEncoding.EncodeToString(streamSHA256)),
		fmt.Sprintf("\"request-signature\": :%s:", requestSignatureB64),
		fmt.Sprintf(
			"\"@signature-params\": (\"stream-digest\" \"request-signature\");created=%d;keyid=%s;tag=%s",
			created, sfString(keyID), sfString(StreamTag)),
	}
	return []byte(strings.Join(lines, "\n"))
}

func sfString(value string) string {
	escaped := strings.ReplaceAll(value, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	return "\"" + escaped + "\""
}

// SignStreamTrailer signs the stream-trailer base for the given stream hash
// and request signature.
func SignStreamTrailer(
	streamSHA256 []byte,
	requestSignatureB64 string,
	created int64,
	signingKey ed25519.PrivateKey,
	keyID string,
) string {
	base := StreamTrailerBase(streamSHA256, requestSignatureB64, keyID, created)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(signingKey, base))
}

// VerifyStreamTrailer verifies a stream-trailer signature against the pinned
// host key.
func VerifyStreamTrailer(
	streamSHA256 []byte,
	requestSignatureB64 string,
	created int64,
	signatureB64 string,
	cfg ResponseVerifyConfig,
) error {
	if created > cfg.Now().Unix()+ResponseCreatedWindowSeconds || created < cfg.Now().Unix()-ResponseCreatedWindowSeconds {
		return authErrorf("stream trailer created timestamp is outside the allowed window")
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return authErrorf("stream trailer signature is not valid base64")
	}
	base := StreamTrailerBase(streamSHA256, requestSignatureB64, cfg.KeyID, created)
	if !ed25519.Verify(cfg.SigningKey, base, signature) {
		return authErrorf("stream trailer signature does not verify")
	}
	return nil
}
