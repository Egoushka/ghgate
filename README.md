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
./ghgate ca --config ghgate.json > ghgate-ca.pem
cat /etc/ssl/certs/ca-certificates.crt ghgate-ca.pem > bundle.pem   # the CA only covers api.github.com and github.com
```

The CA carries x509 name constraints, so it can sign only for the intercepted hosts. Clients trust it through a CA
bundle they are pointed at, never the system store.

## Client setup

Scope the proxy to GitHub traffic only.

- **gh**: a wrapper earlier on `PATH` than the real `gh`:
  ```sh
  #!/bin/sh
  export HTTPS_PROXY=http://127.0.0.1:8899 SSL_CERT_FILE=/path/to/bundle.pem GH_TOKEN=<client token>
  exec /usr/bin/gh "$@"
  ```
- **git**, per URL, so other remotes are untouched:
  ```sh
  git config --global http.https://github.com/.proxy http://127.0.0.1:8899
  git config --global http.https://github.com/.sslCAInfo /path/to/bundle.pem
  ```
  Give git the client token as the Basic password (a credential helper, or `https://x:<client token>@github.com/...`).
- **github-mcp**: set the same `HTTPS_PROXY`, `SSL_CERT_FILE` and `GITHUB_PERSONAL_ACCESS_TOKEN=<client token>` in its
  environment (or on its container).

A client token is checked against the SHA-256 stored in the config, then replaced by the real credential upstream.

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
