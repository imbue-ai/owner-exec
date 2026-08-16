# owner-exec signing profile

A strict profile of [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP
Message Signatures) and [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)
(Content-Digest). "Strict" means the profile pins every choice the RFC leaves
open; a verifier rejects anything outside it. Implementations (the Go daemon,
the Python client, the TypeScript/browser client) must all agree on this
document, checked against `vectors/vectors.json`.

## Keys and identity

- Request signatures use an **Ed25519** key whose public half is present in the
  target's `authorized_keys`. Authorization = possession of a trusted key,
  exactly SSH's model. Non-Ed25519 authorized keys are ignored by exec (they
  may still serve plain SSH).
- Response and stream-trailer signatures use the target endpoint's **SSH host
  key** (`/etc/ssh/ssh_host_ed25519_key`), which the client has pinned out of
  band (the lease/claim response and the synced workspace record).
- `keyid` is the standard OpenSSH SHA256 fingerprint of the signing key.

## Request signatures

- Exactly **one** signature, labelled `sig1`.
- Covered components, in this exact order:
  `("@method" "@path" "content-digest" "x-exec-audience" "x-exec-public-key")`.
- Parameters, in this order: `created`, `expires` (`= created + 60`), `nonce`
  (>= 16 chars), `tag="imbue-owner-exec"`, `keyid` (all required). `alg`, if
  present, must be `ed25519`; it is otherwise omitted (the key type is
  unambiguous from the pinned key).
- Headers the signer sets and the profile covers:
  - `Content-Digest: sha-256=:<base64>:` over the exact request body
    (RFC 9530). Empty body for GET.
  - `X-Exec-Audience: <audience>` -- the value the verifier compares against
    its **own configured audience**, never against the request URL/authority.
    (`ct:<host-id>` for the inner role, `vm:<host-id>` for the vm role.)
  - `X-Exec-Public-Key: <openssh public key line>` -- the key that signed.

### Verifier steps (in order, all required)

1. A configured audience exists (else exec is unavailable) and equals
   `X-Exec-Audience` exactly.
2. `X-Exec-Public-Key` parses as an Ed25519 OpenSSH key and is present in
   `authorized_keys`.
3. `Signature-Input` is exactly one `sig1` member with exactly the covered
   components above and exactly the allowed parameter set; `tag` is
   `imbue-owner-exec`; `keyid` matches the presented key's fingerprint;
   `nonce` is >= 16 chars.
4. `|now - created| <= 60`; `created < expires <= created + 300`; `now < expires`.
5. `Content-Digest` recomputes to match the body.
6. The RFC 9421 signature verifies over the covered components.
7. The nonce is claimed in a replay cache (window = 60s), **last**, so a
   request that fails any earlier check never burns a nonce.

## Response signatures

- Exactly one signature, labelled `sig1`.
- Covered components, in this exact order:
  `("@status" "content-digest" "@method";req "@path";req "signature";key="sig1";req)`.
  The `;req` components bind the response to the exact request that produced it
  (including the request's own signature), so a signed response cannot be
  replayed against a different request. Note the `signature` component's
  parameters serialize `key` before `req` (structured-field insertion order),
  in both the covered-component list and its signature-base line.
- Parameters, in this order: `created`, `tag="imbue-owner-exec-resp"`, `keyid`
  (all required).
- `Content-Digest` covers the exact response body.

### Verifier steps

1. Exactly one `sig1` member with exactly the covered components and parameter
   set; `tag` is `imbue-owner-exec-resp`; `keyid` matches the pinned host key.
2. `|now - created| <= 300`.
3. `Content-Digest` recomputes to match the response body.
4. The RFC 9421 signature verifies (with the request supplied as the
   associated request).

A missing or invalid response signature is treated as tampering, never as an
older server. Clients fail closed.

## Stream-trailer signatures (`/run`)

RFC 9421 signs complete messages, not streams, so `/run` uses one custom
construction. The response streams NDJSON events; after the `exit` event the
server emits a final event:

```json
{"type": "signature", "created": <int>, "keyid": "<fp>", "tag": "imbue-owner-exec-stream", "signature": "<base64>"}
```

The signature is Ed25519 over these exact bytes (the trailer event itself is
NOT part of the hash it signs):

```
"stream-digest": sha-256=:<base64 sha256 of all prior stream bytes>:
"request-signature": :<base64 of the request's sig1 signature>:
"@signature-params": ("stream-digest" "request-signature");created=<int>;keyid="<fp>";tag="imbue-owner-exec-stream"
```

(lines joined with `\n`, no trailing newline). The verifier recomputes the
stream digest over everything before the trailer line, checks `|now - created|
<= 300`, and verifies against the pinned host key. Binding the request
signature stops a captured trailer being replayed for a different request.

## Domain separation

The three `tag` values (`imbue-owner-exec`, `imbue-owner-exec-resp`,
`imbue-owner-exec-stream`) mean a signature made for one kind can never verify
as another. The two audiences (`ct:` / `vm:`) mean an inner-role request
envelope can never verify at the vm-role instance or vice versa, even though
the same key is authorized on both endpoints.

## Threat model

- A fully compromised workspace **container** can drop, delay, or reorder exec
  traffic to the vm instance, but cannot: execute on the VM (it lacks the
  owner's private key), forge or alter a request (signature over method, path,
  body digest, audience), replay an inner envelope at the vm instance
  (audience), replay any envelope past 60s or a used nonce, or tamper with a vm
  response or stream (response/trailer signature over the host key).
- Response signing on the **inner** instance uses the container's host key and
  therefore proves nothing against a compromised container; it is enabled only
  so clients have one uniform verification path. The security guarantee is the
  vm instance's response signature.
- The audience value must come from target-owned state (a baked config on the
  VM, `share.env` inside the container), never inferred from the request, so a
  malicious proxy cannot choose it.
