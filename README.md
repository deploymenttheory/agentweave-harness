# agentweave-harness

An adjudication harness for MCP servers and computer-use agents.

The harness runs as a **separate process** that wraps a governed MCP server: it
spawns the server as a child, proxies the stdio MCP transport between client and
server, and owns every decision about what the server may do — policy
evaluation, audit chain, rug-pull detection, rate limits, approvals, and the
containment ladder. The governed server is reduced to what only it can do:
host-local probes (posture, TPM, device identity) reported up a control channel,
and host-local actuation (firewall, lock, shutdown, credential cleanup) executed
on the harness's command.

The point is the process boundary. A server that evaluates policy in-process is
its own adjudicator — local compromise defeats the controls. Moving adjudication
into a wrapping process the server cannot reach is what makes the controls real.

```
MCP client (Claude)
   |  stdio (MCP)
   v
+---------------------+
|  agentweave-harness |   policy · audit · rug-pull · rate limits · kill decisions
+---------------------+
   |  stdio (MCP,      ^
   |  proxied)         |  control channel: signals up, actuation down
   v                   |
+---------------------+
|  governed MCP server|   tools · host probes · actuators
+---------------------+
```

## Status

**Pre-1.0, under construction.** Phase 0 (this repo state) ships the CLI
skeleton and the ratified design documents. The guardrails packages, proxy, and
control channel land in later phases. First governed server:
[windows-mcp-server](https://github.com/deploymenttheory/windows-mcp-server).

## Documents

| Doc | What it covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Topology, component placement per mode, egress placement, failure modes, phase plan, glossary |
| [docs/wire-protocol.md](docs/wire-protocol.md) | The control-channel protocol (draft until v1.0.0) |
| [docs/scope.md](docs/scope.md) | What this harness does **not** do, and what it never records |
| [docs/roadmap.md](docs/roadmap.md) | Deferred ideas and their provenance |

## License

MIT — see [LICENSE](LICENSE).
