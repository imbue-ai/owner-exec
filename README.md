# owner-exec

An owner-authenticated exec daemon: SSH-equivalent (and VM-level) authority
over a workspace via a small HTTP surface, instead of an SSH session.

`owner-exec` is a single static Go binary. Every request is signed with an
Ed25519 key whose public half must appear in the target's `authorized_keys`
(so authorization is exactly SSH's model: possession of a key the target
trusts), and every response is signed with the target's own SSH host key,
bound to the request it answers. Signing uses a **strict profile of
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP Message Signatures)
and [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) (Content-Digest)** --
see [`spec/profile.md`](spec/profile.md).

It is used by [minds](https://github.com/imbue-ai/mngr) in two roles from one
binary, selected entirely by config:

- **inner** -- inside a workspace container, so a browser-only client can drive
  the workspace (finish a create, provision backups, edit sharing grants)
  without an SSH client. Audience `ct:<host-id>`.
- **vm** -- directly on the remote outer host (an imbue-cloud slice VM or a
  VPS) as root, so the owner can configure everything that runs *outside* the
  container (the latchkey gateway, VM debugging, key rotation, reboot
  recovery). Audience `vm:<host-id>`.

The two audiences make a captured inner envelope useless against the VM
instance and vice versa, even though the same key is authorized on both.

## Why it exists

A web-only workspace has no desktop and no SSH client in the browser, but the
browser needs SSH-equivalent authority. Rather than run an SSH protocol stack
in the browser, this exposes a small HTTP surface -- run a command, read a
file, write a file, read/replace the sharing grants -- authenticated by a
signed envelope. The browser already holds the workspace Ed25519 key (it
generated the keypair at create and stores it encrypted under the account's
data-encryption key). A compromised container can proxy or drop this traffic,
but it can never forge a request or tamper with a VM response.

## Endpoints

- `POST /run` -- body `{"command": ["...", ...], "cwd"?, "timeout_seconds"?}`;
  streams newline-delimited JSON events (`{"type":"stdout"|"stderr","data"}`,
  then `{"type":"exit","code"}`), then a final signed trailer
  `{"type":"signature", ...}` over the exact emitted stream bytes plus the
  request's signature. Clients treat output as unverified until the trailer
  verifies.
- `POST /read-file` -- body `{"path"}`; returns `{"exists", "content_b64"}`.
- `POST /write-file` -- body `{"path", "content_b64", "mode"?}`; atomic write.
- `GET /grants` / `PUT /grants` -- read/replace `data/.secrets/share_grants.toml`
  with a revision compare-and-swap (inner role only). `GET` returns
  `{"grants_toml", "revision"}`; `PUT` accepts an optional `base_revision` and
  refuses a stale write with `409` carrying the current document.
- `GET /_alive` -- unauthenticated liveness (role + version), for supervisor
  and forward-readiness probes.

Every response except `/_alive` is signed per the response profile.

## Configuration

A single TOML file (`--config <path>`):

```toml
role = "vm"                 # "inner" or "vm"
host_id = "host-abcd1234"   # forms the audience: "vm:<host-id>" or "ct:<host-id>"
# audience = "vm:host-..."  # or set the exact audience directly (overrides host_id)
listen_host = "127.0.0.1"
listen_port = 8794
repo_root = "/home/user/workspace"
authorized_keys_path = "/root/.ssh/authorized_keys"
host_key_path = "/etc/ssh/ssh_host_ed25519_key"
grants_enabled = false      # inner role only
share_env_path = ""         # read for the CORS chrome origin (and, inner-only, a share-domain audience fallback)
register_port = false       # inner role: register listen_port into apps.toml at startup
service_name = "owner-exec"
forward_port_script = ""    # path to forward_port.py
```

The vm role requires an `audience` or `host_id`. The inner role may leave both
unset and derive its audience from `SHARE_WORKSPACE_DOMAIN` in `share.env`
(preserving the pre-Go behavior), though a `host_id`-derived `ct:<host-id>`
audience is preferred so exec is available even while unshared.

## Build

```sh
CGO_ENABLED=0 go build -o owner-exec ./cmd/owner-exec
```

Static, dependency-free at runtime. Per-arch release binaries (`x86_64-linux`,
`aarch64-linux`) plus `.sha256` files are published on GitHub releases;
consumers fetch a pinned version and verify the checksum at install time.

## Test vectors

`vectors/vectors.json` holds cross-implementation verification vectors that the
minds Python and TypeScript clients validate against, proving canonicalization
agreement. Regenerate intentionally and commit the result:

```sh
go run ./cmd/gen-vectors > vectors/vectors.json
```

## Development

```sh
go test ./...
gofmt -l .    # must print nothing
go vet ./...
```
