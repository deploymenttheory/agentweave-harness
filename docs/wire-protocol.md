# Control-channel wire protocol

> **Status: DRAFT.** This document is ratified as the design intent, but the
> protocol may change without ceremony until the harness tags v1.0.0. From
> v1.0.0 the protocol is frozen and changes only through version negotiation.

The control channel is the second link between the harness and the governed
server (the first being the proxied MCP stdio stream). Signals flow up;
actuation flows down. The channel deliberately carries **no MCP traffic** and
**no secrets** — see [scope.md](scope.md) for the never-sent list.

## Transport

- **Primary:** Windows named pipe `\\.\pipe\agentweave-<sessionstamp>-<rand128>`,
  created by the harness with an SDDL admitting only the current user and
  SYSTEM.
- **Bootstrap:** the harness passes `AGENTWEAVE_CONTROL_PIPE` (the pipe name)
  and `AGENTWEAVE_CONTROL_TOKEN` (32 random bytes, hex) in the child's
  environment. The server reads both at startup and scrubs them from its
  environment before any tool can observe them (the same discipline
  windows-mcp-server already applies to its secret env vars).
- **Framing:** JSONL — one JSON object per LF-terminated line, UTF-8, maximum
  256 KiB per line. An oversize line is a protocol error and tears the channel
  down.
- **Authentication:** the first server→harness message must carry the token.
  A wrong or missing token means the harness kills the child.

## Envelope

```json
{ "v": 1, "type": "signal.evaluate", "id": "uuid", "re": "uuid", "ts": "RFC3339Nano", "payload": { } }
```

- `id` is present on requests; `re` correlates a response to its request's
  `id`; notifications carry neither.
- `v` is the negotiated protocol version (see below), constant for a session.

## Version negotiation

The server's `hello` carries its supported range `[min, max]`. The harness
picks a version or refuses:

- No overlap → the harness refuses to start the session, with a typed error to
  the operator. **Never run degraded.**
- Unknown message *type* at the negotiated version: notifications are logged
  and ignored; requests get an `error: unsupported` reply.
- Unknown `actuate` rung: **refuse and audit, never guess.** A containment
  command that isn't understood must fail loudly, not approximately.

## Messages: server → harness ("up")

| Type | Payload | Notes |
|---|---|---|
| `hello` | `proto: [min,max]`, `server_version`, `session_stamp`, `token`, `capabilities: {signals: [ids], actuators: [rungs], elevated, run_context}` | First message; carries the token |
| `signal.result` | `re`, `results: [signal results]` | Response to `signal.evaluate` |
| `posture.push` | `results: [...]` | Unsolicited batch after a local cache refresh |
| `heartbeat` | `seq`, `desktop_alive`, `recorder_state` | Desktop-engine liveness — the one thing the proxy cannot infer from MCP frames |
| `credential.event` | `kind: installed\|removed\|injected\|cleanup_done`, `ids` | **Names only, never values or counts of secret characters** |
| `egress.state` | `tier`, `rules_present`, `recovered` | OS-enforcement actuator state |
| `actuate.result` | `re`, `rung`, `ok`, `observed: []`, `skipped_reason?` | What the OS actually reported back |
| `audit.anchor` | `seq`, `head` | Local host-chain head, periodic |
| `plan.evaluate` | `id`, `subjects: [{method, tool, toolset, annotations}]` | The server's planner requests verdicts |

## Messages: harness → server ("down")

| Type | Payload | Notes |
|---|---|---|
| `hello.ack` | `proto`, `mode: enforce\|observe`, `effective_config: {enforce_https, protected_paths, banner, egress_proxy_port?, heartbeat_interval}` | Config the server must apply before building its tool surface |
| `signal.evaluate` | `id`, `ids: [signal-ids]`, `args` | **By declared signal id only — there is no generic shell/exec verb, by construction** |
| `actuate` | `id`, `rung`, `params` | Rungs: `banner`, `seal`, `finalize_recording`, `credential_cleanup`, `isolate`, `kill_procs`, `lock`, `shutdown`, `egress_apply`, `egress_suspend`, `egress_restore` |
| `plan.verdict` | `re`, verdict | Answer to `plan.evaluate` |
| `config.update` | `effective_config` | e.g. a session-manifest expiry flipping mid-session |
| `shutdown` | `reason`, `graceful: true` | Orderly end of session |
| `audit.anchor` | `seq`, `head` | Harness-chain head, so the server chain also pins the pair |

## What the harness derives from the proxied MCP frames alone

Because every MCP frame passes through the harness, the following need **no**
server-side reporting: audit of MCP traffic, rug-pull fingerprints (hashes over
parsed `tools/list` / `prompts/list` / `resources/list` / `server/discover`
responses, plus periodic harness-injected re-lists), rate-limit accounting, and
verdict subjects.

What still requires the control channel: posture/signal probe results,
desktop-engine heartbeat, credential lifecycle events, egress OS-enforcement
state, actuation outcomes, TPM attestation.

## Channel-loss semantics

- **Server (harness mode):** pipe EOF or read error → clean up credentials,
  finalize any recording, seal the local chain, exit non-zero. (Belt and
  braces: stdin EOF from a dead harness already ends the MCP session; the
  channel watcher covers the half-dead case.)
- **Harness:** child exit or pipe EOF → append `server.lost` to its chain,
  seal, synthesize a JSON-RPC error for any in-flight client request, close
  client stdio, exit non-zero. **Never keep serving from cache.**
- **Standalone server:** no channel exists; today's behavior (audit-only
  default). There is no runtime degradation from harness mode to standalone —
  a session is born in one mode and dies in it.

## Kill-ladder ordering over the channel

The harness owns the ladder's ordering and dispatches rungs individually. The
transparency rungs — `banner`, `seal`, `finalize_recording` (and the harness
sealing its own chain) — are always dispatched **before** any containment rung
(`isolate`, `kill_procs`, `lock`, `shutdown`), or the forensic trail is lost.
The server executes each rung with its existing skip-and-audit semantics
(missing elevation skips a rung and reports it; half a containment beats none
mid-incident) and reports `observed` back.
