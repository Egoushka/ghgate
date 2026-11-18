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
| The proxy becomes an open relay to the internet. | Tunnelling other hosts can be switched off (`tunnel_others: false`). The listener is not public. |
| Cache poisoning or a cross-identity leak: a write-scoped answer is served to a read-only client. | The cache key includes the credential kind. Entries are stored only from upstream responses. Every hit is revalidated, so a revoked resource answers 404 upstream and the entry is dropped. |
| Secrets end up in logs. | No token, `Authorization` value or body is ever logged; AC10 tests it. |
| A GraphQL mutation hidden from the parser gets the read credential. | The read credential has fewer rights than the write one, so a misrouted mutation fails rather than escalating. |

**Did we do a good enough job.** Every mitigation above has an acceptance check in `SPEC.md`, except "not public",
which is a property of the deployment.

## Accepted risks

None yet.
