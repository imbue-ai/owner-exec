// Command gen-vectors writes the cross-implementation test vectors
// (vectors/vectors.json) that the Python and TypeScript clients validate
// against.
//
// The vectors are VERIFICATION vectors: each carries a real signed envelope
// plus the exact clock (`verify_at`) and inputs at which it must verify, and
// an `expect_valid` flag. Clients run their own verifier against them at
// `verify_at`, which proves canonicalization agreement across implementations
// without depending on byte-identical signatures (created/nonce vary per run).
//
// Regenerate intentionally and commit the result:
//
//	go run ./cmd/gen-vectors > vectors/vectors.json
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/imbue-ai/owner-exec/internal/profile"
)

func fixedKey(seedByte byte) (ed25519.PrivateKey, string) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	line, err := profile.PublicKeyLine(private.Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	return private, line
}

// requestVector is a signed request the client verifies (request-verify side).
type requestVector struct {
	Name              string            `json:"name"`
	ExpectValid       bool              `json:"expect_valid"`
	Method            string            `json:"method"`
	URL               string            `json:"url"`
	Audience          string            `json:"audience"`
	AuthorizedKeyLine string            `json:"authorized_key_line"`
	BodyB64           string            `json:"body_b64"`
	VerifyAt          int64             `json:"verify_at"`
	Headers           map[string]string `json:"headers"`
}

// responseVector is a signed response the client verifies against a pinned
// host key, bound to the request that produced it.
type responseVector struct {
	Name           string            `json:"name"`
	ExpectValid    bool              `json:"expect_valid"`
	StatusCode     int               `json:"status_code"`
	HostKeyLine    string            `json:"host_key_line"`
	HostKeyID      string            `json:"host_key_id"`
	RequestHeaders map[string]string `json:"request_headers"`
	RequestMethod  string            `json:"request_method"`
	RequestURL     string            `json:"request_url"`
	BodyB64        string            `json:"body_b64"`
	VerifyAt       int64             `json:"verify_at"`
	Headers        map[string]string `json:"headers"`
}

// streamVector is a signed stream trailer the client verifies.
type streamVector struct {
	Name             string `json:"name"`
	ExpectValid      bool   `json:"expect_valid"`
	HostKeyLine      string `json:"host_key_line"`
	HostKeyID        string `json:"host_key_id"`
	StreamBytesB64   string `json:"stream_bytes_b64"`
	RequestSignature string `json:"request_signature"`
	Created          int64  `json:"created"`
	VerifyAt         int64  `json:"verify_at"`
	Signature        string `json:"signature"`
}

type vectorFile struct {
	Description string           `json:"description"`
	Requests    []requestVector  `json:"requests"`
	Responses   []responseVector `json:"responses"`
	Streams     []streamVector   `json:"streams"`
}

func headerMap(header http.Header, names ...string) map[string]string {
	out := map[string]string{}
	for _, name := range names {
		if value := header.Get(name); value != "" {
			out[name] = value
		}
	}
	return out
}

var signedHeaderNames = []string{
	"Content-Digest", "X-Exec-Audience", "X-Exec-Public-Key", "Signature-Input", "Signature",
}

func signedRequest(method, url string, body []byte, audience, nonce string, key ed25519.PrivateKey, line string) *http.Request {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	if err := profile.SignRequest(req, body, audience, key, line, nonce); err != nil {
		panic(err)
	}
	return req
}

func createdOf(req *http.Request) int64 {
	created, err := profile.SignatureCreated(req.Header.Get("Signature-Input"))
	if err != nil {
		panic(err)
	}
	return created
}

func main() {
	clientKey, clientLine := fixedKey(1)
	_, otherLine := fixedKey(2)
	hostKey, hostLine := fixedKey(9)
	hostSSHPub, _, err := profile.ParsePublicKeyLine(hostLine)
	if err != nil {
		panic(err)
	}
	hostKeyID := profile.Fingerprint(hostSSHPub)

	file := vectorFile{
		Description: "owner-exec RFC 9421/9530 strict-profile cross-implementation VERIFICATION vectors. " +
			"Each envelope is verified by the client at verify_at against the given inputs; expect_valid " +
			"states the outcome. Signatures are not byte-compared (created/nonce vary per regeneration).",
	}

	// -- request vectors (valid) --
	runBody := []byte(`{"command":["echo","hello"]}`)
	runReq := signedRequest("POST", "http://127.0.0.1:8793/run", runBody, "vm:host-abcd", "nonce-0123456789abcdef", clientKey, clientLine)
	file.Requests = append(file.Requests, requestVector{
		Name: "run-valid", ExpectValid: true, Method: "POST", URL: "http://127.0.0.1:8793/run",
		Audience: "vm:host-abcd", AuthorizedKeyLine: clientLine, BodyB64: base64.StdEncoding.EncodeToString(runBody),
		VerifyAt: createdOf(runReq), Headers: headerMap(runReq.Header, signedHeaderNames...),
	})

	readBody := []byte(`{"path":"data/example.txt"}`)
	readReq := signedRequest("POST", "http://127.0.0.1:8793/read-file", readBody, "container:host-abcd", "nonce-fedcba9876543210", clientKey, clientLine)
	file.Requests = append(file.Requests, requestVector{
		Name: "read-file-valid", ExpectValid: true, Method: "POST", URL: "http://127.0.0.1:8793/read-file",
		Audience: "container:host-abcd", AuthorizedKeyLine: clientLine, BodyB64: base64.StdEncoding.EncodeToString(readBody),
		VerifyAt: createdOf(readReq), Headers: headerMap(readReq.Header, signedHeaderNames...),
	})

	// -- request vectors (invalid) --
	// Unauthorized key: verify against a different authorized key.
	file.Requests = append(file.Requests, requestVector{
		Name: "run-unauthorized-key", ExpectValid: false, Method: "POST", URL: "http://127.0.0.1:8793/run",
		Audience: "vm:host-abcd", AuthorizedKeyLine: otherLine, BodyB64: base64.StdEncoding.EncodeToString(runBody),
		VerifyAt: createdOf(runReq), Headers: headerMap(runReq.Header, signedHeaderNames...),
	})
	// Wrong audience: verifier configured with a different audience.
	file.Requests = append(file.Requests, requestVector{
		Name: "run-wrong-audience", ExpectValid: false, Method: "POST", URL: "http://127.0.0.1:8793/run",
		Audience: "vm:host-different", AuthorizedKeyLine: clientLine, BodyB64: base64.StdEncoding.EncodeToString(runBody),
		VerifyAt: createdOf(runReq), Headers: headerMap(runReq.Header, signedHeaderNames...),
	})
	// Tampered body: same headers, different body.
	tamperedRun := headerMap(runReq.Header, signedHeaderNames...)
	file.Requests = append(file.Requests, requestVector{
		Name: "run-tampered-body", ExpectValid: false, Method: "POST", URL: "http://127.0.0.1:8793/run",
		Audience: "vm:host-abcd", AuthorizedKeyLine: clientLine,
		BodyB64:  base64.StdEncoding.EncodeToString([]byte(`{"command":["rm","-rf","/"]}`)),
		VerifyAt: createdOf(runReq), Headers: tamperedRun,
	})
	// Expired: verify far past the window.
	file.Requests = append(file.Requests, requestVector{
		Name: "run-expired", ExpectValid: false, Method: "POST", URL: "http://127.0.0.1:8793/run",
		Audience: "vm:host-abcd", AuthorizedKeyLine: clientLine, BodyB64: base64.StdEncoding.EncodeToString(runBody),
		VerifyAt: createdOf(runReq) + 100000, Headers: headerMap(runReq.Header, signedHeaderNames...),
	})

	// -- response vector (valid, bound to the run request) --
	respBody := []byte(`{"written":true}`)
	respHeader := http.Header{}
	respHeader.Set("Content-Type", "application/json")
	respHeader.Set(profile.ContentDigestHeader, profile.ContentDigest(respBody))
	respInput, respSig, err := profile.SignResponse(200, respHeader, runReq, hostKey, hostKeyID)
	if err != nil {
		panic(err)
	}
	respHeader.Set("Signature-Input", respInput)
	respHeader.Set("Signature", respSig)
	respCreated, err := profile.SignatureCreated(respInput)
	if err != nil {
		panic(err)
	}
	requestHeaders := headerMap(runReq.Header, "Signature")
	file.Responses = append(file.Responses, responseVector{
		Name: "run-response-valid", ExpectValid: true, StatusCode: 200, HostKeyLine: hostLine, HostKeyID: hostKeyID,
		RequestHeaders: requestHeaders, RequestMethod: "POST", RequestURL: "http://127.0.0.1:8793/run",
		BodyB64: base64.StdEncoding.EncodeToString(respBody), VerifyAt: respCreated,
		Headers: headerMap(respHeader, "Content-Digest", "Signature-Input", "Signature"),
	})
	// Response replayed against a different request must be invalid.
	otherReq := signedRequest("POST", "http://127.0.0.1:8793/run", []byte(`{"command":["ls"]}`), "vm:host-abcd", "nonce-aaaaaaaaaaaaaaaa", clientKey, clientLine)
	file.Responses = append(file.Responses, responseVector{
		Name: "run-response-wrong-request", ExpectValid: false, StatusCode: 200, HostKeyLine: hostLine, HostKeyID: hostKeyID,
		RequestHeaders: headerMap(otherReq.Header, "Signature"), RequestMethod: "POST", RequestURL: "http://127.0.0.1:8793/run",
		BodyB64: base64.StdEncoding.EncodeToString(respBody), VerifyAt: respCreated,
		Headers: headerMap(respHeader, "Content-Digest", "Signature-Input", "Signature"),
	})

	// -- stream vector (valid) --
	requestSignature, err := profile.ExtractRequestSignature(runReq.Header)
	if err != nil {
		panic(err)
	}
	streamBytes := []byte(`{"type":"stdout","data":"hello\n"}` + "\n" + `{"type":"exit","code":0}` + "\n")
	streamDigest := sha256.Sum256(streamBytes)
	streamCreated := int64(1755300000)
	streamSig := profile.SignStreamTrailer(streamDigest[:], requestSignature, streamCreated, hostKey, hostKeyID)
	file.Streams = append(file.Streams, streamVector{
		Name: "run-stream-valid", ExpectValid: true, HostKeyLine: hostLine, HostKeyID: hostKeyID,
		StreamBytesB64: base64.StdEncoding.EncodeToString(streamBytes), RequestSignature: requestSignature,
		Created: streamCreated, VerifyAt: streamCreated, Signature: streamSig,
	})
	// Tampered stream bytes must be invalid (verifier recomputes the digest).
	file.Streams = append(file.Streams, streamVector{
		Name: "run-stream-tampered", ExpectValid: false, HostKeyLine: hostLine, HostKeyID: hostKeyID,
		StreamBytesB64: base64.StdEncoding.EncodeToString(append(streamBytes, 'x')), RequestSignature: requestSignature,
		Created: streamCreated, VerifyAt: streamCreated, Signature: streamSig,
	})

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(file); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
