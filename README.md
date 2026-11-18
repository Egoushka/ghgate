# ghgate

A GitHub gateway for AI agents: a forward proxy that caches and coalesces reads, revalidates every hit with ETags
(GitHub does not count a `304`), spends reads on a GitHub App's own rate-limit bucket and writes on yours, and keeps the
real tokens away from the agents. Unmodified `gh`, `git` and github-mcp work through it.

Status: v0 in progress. See [SPEC.md](SPEC.md) and [THREAT-MODEL.md](THREAT-MODEL.md).

MIT licensed.
