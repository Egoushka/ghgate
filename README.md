# ghgate

A GitHub gateway for AI agents: a forward proxy that caches and coalesces reads, revalidates every hit with ETags
(GitHub does not count a `304`), spends reads on a GitHub App's own rate-limit bucket and writes on yours, and keeps the
real tokens away from the agents. Unmodified `gh`, `git` and github-mcp work through it.

Status: v0. See [SPEC.md](SPEC.md) and [THREAT-MODEL.md](THREAT-MODEL.md).

## Quick start

```sh
go build -o ghgate ./cmd/ghgate
cp ghgate.example.json ghgate.json          # fill in credentials; printf %s "$TOKEN" | ./ghgate hash-token for each client
./ghgate serve --config ghgate.json &       # proxy on 127.0.0.1:8899, stats on 127.0.0.1:8898
./ghgate ca --config ghgate.json > ghgate-ca.pem   # one CA certificate per intercepted host
cat /etc/ssl/certs/ca-certificates.crt ghgate-ca.pem > bundle.pem   # each CA covers exactly its own host
```

Each intercepted host has its own CA with x509 name constraints: it can sign for that exact host only, not for its
subdomains, IP addresses, emails or URIs. Checked with Go and with OpenSSL (`openssl verify`: `evil.github.com` fails with
"excluded subtree violation"). A CA left from an older single-CA state directory is refused at start-up; move `ca.pem` and
`ca.key` out of `state_dir` and re-trust the new bundle. Clients trust it through a CA
bundle they are pointed at, never the system store.

## Client setup

Scope the proxy to GitHub traffic only.

- **gh**: a wrapper earlier on `PATH` than the real `gh`:
  ```sh
  #!/bin/sh
  export HTTPS_PROXY=http://x:<client token>@127.0.0.1:8899 SSL_CERT_FILE=/path/to/bundle.pem GH_TOKEN=<client token>
  exec /usr/bin/gh "$@"
  ```
- **git**, per URL, so other remotes are untouched:
  ```sh
  git config --global http.https://github.com/.proxy http://x:<client token>@127.0.0.1:8899
  git config --global http.https://github.com/.sslCAInfo /path/to/bundle.pem
  ```
  Give git the client token as the Basic password (a credential helper, or `https://x:<client token>@github.com/...`).
- **github-mcp**: set the same `HTTPS_PROXY` (with the token in it), `SSL_CERT_FILE` and `GITHUB_PERSONAL_ACCESS_TOKEN=<client token>` in its
  environment (or on its container).

A client token is checked against the SHA-256 stored in the config, then replaced by the real credential upstream.

**The token goes in the proxy URL too.** `CONNECT` itself needs the client token as `Proxy-Authorization`, or ghgate answers
`407`. Checked: Go's `net/http` (so `gh`) sends the userinfo of `HTTPS_PROXY=http://x:TOKEN@host:port` as a Basic
`Proxy-Authorization` on the first `CONNECT`; git (libcurl) sends none at first, gets the `407` with
`Proxy-Authenticate: Basic`, and retries on the same connection with it (git 2.39.5). Inside the tunnel the usual
`Authorization` check still applies.

**Tunnelling other hosts** is off by default (`tunnel_others`). When on, it refuses loopback, private, link-local, CGNAT
and other internal destinations, and the admin listener.

**GitHub App mode.** A request with an owner in the path (`/repos/o/...`, `/orgs/o`, `/users/o`) uses that owner's
installation. A request without one (GraphQL, `/user`, `/repositories/N`) uses the installation of `default_owner` when
you set it. Otherwise only clients with `can_write` get it, read with the `write` credential; a read-only client gets `403` before
anything goes upstream. GraphQL answers a repository the installation cannot see with `200` and partial data, not a 404, so the
write-credential retry does not cover it.

**Read-only clients and git.** A client without `can_write` gets git upload-pack on `github.com` and nothing else there:
no LFS batch, no archive or raw downloads, no web pages. Give such a client `can_write`, or use the API, for those.

## How it differs

- [ghx](https://github.com/brunoborges/ghx) wraps `gh` commands with a 30 s TTL cache on one machine, and passes
  `run watch` through. ghgate works one layer down, at the HTTP proxy, so any client is covered.
- Prow's [ghproxy](https://docs.prow.k8s.io/docs/ghproxy/) is an ETag reverse proxy and needs clients that can change
  their API base URL. ghgate is a standard forward proxy.
- ghgate also revalidates every cache hit (nothing is stale), splits read and write credentials, never hands the real
  credentials to agents, and counts calls per agent.

## Behaviour in short

Reads (`GET`, and GraphQL documents without a `mutation`) use the read credential and are cached. Everything else uses the
write credential and needs `can_write`; a write drops the cached entries of the repo it touched. Below `floor` remaining
calls, reads get `429` with `Retry-After`. `GET /stats` and `GET /healthz` are on the admin listener. Logs are one JSON
line per request and never hold tokens, query strings or bodies.

Tests: `go vet ./... && go test -race ./...`. Live check: `scripts/e2e.sh` (needs a real PAT).

MIT licensed.
