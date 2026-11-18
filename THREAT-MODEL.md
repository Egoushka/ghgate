# Threat model

**What we are working on.**
- ghgate is a forward proxy that agents use to reach GitHub.
- It holds the real GitHub credentials: a PAT, often with admin rights, and a GitHub App private key.
- It holds a CA that it uses to intercept `api.github.com` and `github.com` for its own clients.

**What can go wrong, and what we do about it.**

| Threat | Mitigation |
|---|---|
| A stolen CA key lets someone intercept any TLS site for clients that trust it. | x509 name constraints limit the CA to the intercepted GitHub hosts. Clients trust it only through `SSL_CERT_FILE`/`sslCAInfo`, never the system store. The key file is mode 0600. |
| Anyone who reaches the listener spends the owner's PAT. | Every intercepted request needs a client token. Only SHA-256 hashes are stored. The listener binds to loopback or a private address, never `0.0.0.0` by default. |
| An agent that should only read pushes or merges. | `can_write` per client; without it, every write method, GraphQL mutation and `git-receive-pack` gets 403. |
| The proxy becomes an open relay, or a way into the internal network. | `tunnel_others` defaults to false. `CONNECT` itself needs the client token (`Proxy-Authorization`, else 407). Tunnels refuse loopback, private, link-local, ULA, CGNAT, unspecified and multicast addresses, checked on the dialled IP so DNS rebinding cannot get past it, never reach the admin listener, and close when idle. The listener is not public. |
| Cache poisoning or a cross-identity leak: a write-scoped answer is served to a read-only client. | The cache key includes the credential kind, and the write-credential retry after a 404/403 happens only for clients with `can_write` (read-only clients never see an answer fetched with the write credential). Entries are stored only from upstream responses. Every hit is revalidated, so a revoked resource answers 404 upstream and the entry is dropped. |
| Secrets end up in logs. | No token, `Authorization` value or body is ever logged; AC10 tests it. |
| A GraphQL mutation hidden from the parser gets the read credential. | The body must be one object with exactly the keys `query`, `variables`, `operationName` (matched case-sensitively, no duplicates); batches and anything unparseable are writes. The read credential has fewer rights than the write one, so a misrouted mutation fails rather than escalating. When no separate read credential exists, every GraphQL POST needs `can_write`. |
| A read-only client pushes through `github.com`, or smuggles a method (`X-HTTP-Method-Override`). | Only exact upload-pack paths are read-only (percent-encoding and `;` are refused); everything else on `github.com` needs `can_write`. Method-override headers are stripped before anything goes upstream. |

**Did we do a good enough job.** Every mitigation above has an acceptance check in `SPEC.md`, except "not public",
which is a property of the deployment.

## Accepted risks

- **The CA constraint covers subdomains.** A DNS name constraint of `github.com` permits every `*.github.com`, so a leaked CA key can forge `evil.github.com` for clients that trust the CA. IP, email and URI names are excluded outright. AC9 pins this behaviour. The key file is mode 0600 and ghgate refuses to start when the key or state directory is group- or world-accessible.
- **App mode without an owner in the path** (GraphQL, `/user`) uses the lowest-id installation. GraphQL answers an unreachable repository with `200` and partial data, so the 404/403 retry cannot repair that.
