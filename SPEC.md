# ghgate v0: spec

**What:** an HTTP forward proxy that sits between AI agents and GitHub. It caches reads, coalesces repeated ones and
spends them on a separate budget. It holds the real credentials so the agents don't have to.

**Why:** every token of one GitHub user shares one 5,000 calls/h REST bucket. A fleet of agents empties it.
Measured 2026-11-18: one default `gh run watch` spent ~80 calls/min. The only GitHub traffic that does not draw on
the bucket:
- a `304 Not Modified` answer to a conditional request (measured free, 2026-10-29);
- a GitHub App installation token, which has its own bucket;
- git transport;
- webhooks.

ghgate turns as many reads as it can into the first two. Agents keep using unmodified `gh`, `git` and
github-mcp.

**Prior art, and the difference:**
- [ghx](https://github.com/brunoborges/ghx) (MIT) wraps `gh` *commands* with a 30 s TTL cache on one machine. It passes `run watch` through.
- Prow's [ghproxy](https://docs.prow.k8s.io/docs/ghproxy/) is an ETag reverse proxy, which needs clients that can change their API base URL.

ghgate works at the HTTP layer of a standard forward proxy, so any client is covered. It also:
- revalidates every cache hit, so nothing is stale;
- splits read and write credentials;
- never gives the real credentials to the agents;
- counts calls per agent.

**Measurable bet:** one hour of normal agent work through ghgate moves the user's `core.used` by under 300 calls,
against ~1,800 without it (measured 2026-11-18). **Stop if** gh or git refuses the MITM chain on a stock install, or a
cached answer makes a waiting tool such as `ws wait` decide wrongly.

## Behaviour

**Listener.** `ghgate serve --config ghgate.json` runs an HTTP proxy that accepts `CONNECT`.
- **Intercepted hosts:** `api.github.com` and `github.com`, configurable. ghgate terminates TLS for them with a leaf certificate signed by its own CA.
- **The CA:**
  - There is **one CA per intercepted host**, generated on first start (ECDSA P-256) into `state_dir/ca/<host>/`, with the key at mode 0600.
  - Each CA's **x509 name constraints** permit only its exact host (for `github.com`: permitted `github.com`, excluded `.github.com`) and exclude all IP, email and URI names. A leaked key therefore forges one host and nothing else, not even its subdomains.
  - A CA left over from the old single-CA layout (`state_dir/ca.pem`) is refused at start-up with a message.
  - `ghgate ca` prints the bundle of all CA certificates (public certificates only, never keys). The admin listener serves the same bytes at `GET /ca.pem` (`Content-Type: application/x-pem-file`): this is how clients fetch the CA when ghgate runs in a container.
- **Every other host** is tunnelled byte for byte, without interception, only when `tunnel_others` is true (default false). Tunnels refuse loopback, private, link-local, ULA, CGNAT, unspecified and multicast destinations (checked on the resolved address) and the admin listener, and close after 5 min idle.
- **`CONNECT` needs the client token** as `Proxy-Authorization` (Basic with the token as the password, or Bearer); without it the answer is `407`.
- **Admin listener.** A second listener, on loopback by default, serves `GET /stats`, `GET /healthz` and `GET /ca.pem`. It has no authentication, so it stays on loopback or a private network such as the tailnet.
- **Health check without a shell.** `ghgate healthcheck --config ghgate.json` GETs `/healthz` on the config's `admin` address and exits 0 on `200`, else 1. A wildcard admin address (`0.0.0.0:8898`, `:8898`, `[::]:8898`) is dialled on loopback.

**Client identity.** Every intercepted request must carry a client token from the config, in one of two places:
- `Authorization: token|Bearer <t>`, for the API;
- `Basic` with the token as the password, for git.

Rules:
- The config stores the SHA-256 of each client token, together with a name and `can_write`.
- A missing or unknown token gets `401` with a JSON message. Nothing is sent upstream.
- The client's own `Authorization` is never forwarded.

**Upstream credentials.** The config has a `read` credential and a `write` credential. Each is one of:
- `{"pat_file": path}`. The file is re-read when its mtime changes, so a rotation needs no restart.
- `{"pat_env": "NAME"}`. The token is the value of environment variable `NAME`, read once at start (a rotation needs a restart). An unset or empty variable stops the start with an error naming the variable.
- `{"app": {"id": N, "key_file": path}}`. ghgate mints an installation token for each owner, finding the installation through `GET /app/installations`, and renews it 10 min before it expires. `{"app": {"id": N, "key_env": "NAME"}}` takes the key from environment variable `NAME` instead, read once at start: the value is PEM text (it contains `-----BEGIN`) or the base64 of that PEM. A bad value stops the start; errors name the variable and never print the value.

Exactly one of `pat_file`, `pat_env` or `app` per credential, and exactly one of `key_file` or `key_env` per App; anything else is rejected at load. Environment variables exist for containers, where secrets reach the process only as environment (an `env_file`) and the image has no shell.

When `read` is omitted, it falls back to `write`; every GraphQL POST then needs `can_write`, because it runs with the write credential. Two entries are one credential when they name the same `pat_file` (after resolving symlinks), the same `pat_env`, or the same App id.

**App mode and the owner.** A request names an owner in the path (`/repos/o/...`, `/orgs/o`, `/users/o`). One without (GraphQL, `/user`, `/repositories/N`) uses the installation of `default_owner` when that is set. Otherwise only clients with `can_write` get it, read with the `write` credential; a read-only client gets `403` before anything goes upstream (gate r3). There is no "first installation" guess. GraphQL answers a repository the installation cannot see with `200` and partial data, so the 404/403 retry does not cover it. A failed `/app/installations` load is not retried for 60 s.

**Routing.**

| Request | Credential | Cache |
|---|---|---|
| `GET`/`HEAD` on the API | read; if read answers 404 or 403 (not a rate-limit 403), retried once with write, for a client with `can_write` only and while the bucket is above `floor` (the App may not be installed on that repo) | yes |
| `POST /graphql` whose body is exactly one object with the keys `query`, `variables`, `operationName` and a document with only queries (a batch, a duplicate or unknown key, or anything unparseable is a write) | read (with the same 404/403 retry) | no; identical concurrent bodies are coalesced |
| `POST /graphql` with a mutation, and any other method on the API | write. `403` when the client lacks `can_write` | no; it invalidates cached entries under the `/repos/{owner}/{repo}` it touched |
| `github.com` (git smart HTTP, web) | write, as Basic `x-access-token:<token>`. A client without `can_write` gets git upload-pack only: no LFS batch, no archive or raw `GET`s, no web pages. Only `GET /{o}/{r}[.git]/info/refs?service=git-upload-pack` and `POST /{o}/{r}[.git]/git-upload-pack` are open to read-only clients; everything else needs `can_write` | no, streamed |

**Cache.**
- **Key:** credential kind (`read` or `write`), method, full URL, and the `Accept` and `X-GitHub-Api-Version` headers.
- **Storage:** an in-memory LRU, capped by `cache_mb` (default 256). It stores the status, the headers and the body of 200 responses that carry an `ETag` or `Last-Modified`.
- **A hit** is always revalidated upstream with `If-None-Match` / `If-Modified-Since`. A `304` serves the stored body with status 200. Optional `fresh_for_ms` (default 0) serves a hit without revalidating when the entry was validated less than that long ago.
- **Coalescing:** concurrent identical GETs share one upstream request (singleflight).
- **Response header:** `X-Ghgate-Cache: miss|revalidated|fresh|coalesced|bypass`.

**Floor.**
- ghgate tracks `x-ratelimit-remaining` and `-reset` from upstream responses, per credential and per resource (`core`, `graphql`).
- Below `floor` (default 300), reads on that credential get `429` with `Retry-After` and a JSON message an agent can act on: when the bucket resets, how many calls are left, how to spend less. Nothing is sent upstream.
- Writes still pass until `write_floor` (default 50).

**Stats.** `/stats` returns JSON:
- per client: requests, cache outcomes, upstream calls, refusals;
- per credential: the last-seen remaining and reset per resource.

**Never logged:** tokens, `Authorization` values or request bodies. Logs are one JSON line per request: client name, method, host, path without the query string, status, cache outcome, upstream ms.

**Stack:** Go standard library only. There is one external module at most, `golang.org/x/sync/singleflight`, and even that can be written in about 30 lines.

## Acceptance checks (`go test ./...`, fake upstream on `httptest` TLS)

| # | Check |
|---|---|
| AC1 | The second identical GET sends `If-None-Match`. The upstream answers 304, and the client receives 200 with the first body and `X-Ghgate-Cache: revalidated`. |
| AC2 | 50 concurrent identical GETs make 1 upstream request. |
| AC3 | GET and a GraphQL `query` reach upstream with the read token. POST, PATCH, DELETE and a GraphQL `mutation` reach it with the write token. The client token never reaches upstream. |
| AC4 | A missing or unknown client token gets 401, with 0 upstream requests. A client without `can_write` gets 403 on a write. |
| AC5 | A `POST /repos/o/r/issues` drops the cached `GET /repos/o/r/issues` (the next GET is a `miss`), and keeps `/repos/o/other`. |
| AC6 | Below the floor, a read gets 429 with `Retry-After`, with 0 upstream requests. A write still passes. |
| AC7 | A read answered 404 by the read credential is retried once with the write credential, for a client with `can_write`. A client without it gets the 404. |
| AC8 | CONNECT to a host that is not intercepted is tunnelled: the client sees the origin's own certificate. |
| AC9 | A leaf certificate for `api.github.com` verifies against its CA. Leaves that ghgate is made to sign for `example.com`, for `evil.github.com` (from the `github.com` CA), or with an IP, email or URI name fail verification (name constraints), in Go and in OpenSSL. |
| AC10 | Captured logs contain no client or upstream token substring. |
| AC11 | App mode: against a fake `/app/installations` and `/access_tokens`, ghgate mints a token per owner, uses it for that owner's reads and renews it before expiry. |
| AC12 | A PAT file rewritten on disk is used on the next request, without a restart. |

**Live check** `scripts/e2e.sh`, run by hand, needing network and a real PAT:
- `GH_TOKEN=<client token> HTTPS_PROXY=… SSL_CERT_FILE=<bundle> gh api repos/cli/cli` twice. The second answer is `revalidated`, and `core.used` does not move on the second call.
- `git ls-remote` of a private repo succeeds through the proxy.

## Client setup (documented in the README)

Scope the proxy to GitHub traffic only, so nothing else goes through it:
- `gh`: a wrapper on `PATH` that sets `HTTPS_PROXY`, `SSL_CERT_FILE` and `GH_TOKEN=<client token>`, then runs the real `gh`.
- `git`: `http.https://github.com/.proxy` and `http.https://github.com/.sslCAInfo`.
- github-mcp: the same environment on its container.

## Not in v0

- A disk cache.
- Per-client budgets.
- Webhook-fed state, so that waiting costs 0 calls.
- An MCP endpoint with compact, agent-shaped answers.
- A dashboard.
