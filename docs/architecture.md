# Architecture

agentweave-harness is a separate process that wraps a governed MCP server. It
owns adjudication; the server owns capability. This document is the ratified
design for that split: what runs where, why, and in what order it gets built.

## Why a separate process

The first governed server, windows-mcp-server, was built self-adjudicating: its
policy engine, audit chain, rug-pull detection, kill switch and egress control
run in-process with the tools they govern. The controls are well designed, but
the placement gives them a ceiling: a process cannot durably police itself, and
any compromise of the tool surface is a compromise of the adjudicator.

This is not a hypothetical weakness. cua's permission-policy documentation
states its engine is "evaluated in-process, so local compromise defeats it;
remote agents get a real boundary." The harness exists to provide precisely the
boundary that in-process engines concede they lack: the policy decision, the
audit record, and the containment order all happen in a process the governed
server cannot reach.

## Topology

```
MCP client (Claude Desktop / Claude Code / any MCP host)
   |
   |  stdio (MCP, JSON-RPC frames)
   v
+---------------------------------------------------------------+
|  agentweave-harness                                           |
|    - MCP stdio proxy: frame pump, id remapping, injection     |
|    - policy load (layered) + engine + signal cache            |
|    - verdicts + refusal synthesis (5 decidable methods)       |
|    - authoritative audit chain (MCP frames + verdicts)        |
|    - rug-pull fingerprints from the wire                      |
|    - rate limits, approvals, plan adjudication                |
|    - heartbeat monitor, kill-ladder ordering                  |
|    - egress loopback proxy (harness mode)                     |
|    - GuardrailStatus / Kill tools (injected, answered here)   |
+---------------------------------------------------------------+
   |                                        ^
   |  stdio (MCP, proxied)                  |  control channel (named pipe,
   v                                        |  JSONL): signals up,
+---------------------------------------------------------------+
|  governed MCP server (e.g. windows-mcp-server --harness)      |
|    - the tool surface (desktop automation, ...)               |
|    - host probes: posture, TPM, device identity, run context  |
|    - actuators: banner, isolate, kill, lock, shutdown,        |
|      credential cleanup, egress OS enforcement                |
|    - credentials subsystem (never-read invariant, never       |
|      crosses the process boundary)                            |
|    - local host-events audit chain, cross-anchored            |
+---------------------------------------------------------------+
```

The harness spawns the server as a child. Every MCP frame passes through the
harness, so enforcement happens where the server cannot bypass it. A second
local channel (see [wire-protocol.md](wire-protocol.md)) carries signals up and
actuation down.

## Component placement per mode

### agentweave-harness process (harness mode)

| Component | Notes |
|---|---|
| MCP stdio proxy | Byte-faithful when not intervening; JSON-RPC id remapping; can inject harness-originated requests (e.g. re-lists) |
| Policy engine | Layered documents (see below); signal cache fed over the control channel |
| Verdicts + refusals | All five decidable methods: `tools/call`, `resources/read`, `prompts/get`, `completion/complete`, `subscriptions/listen`. Refusal shape per method: `IsError` result for `tools/call`, JSON-RPC error for the rest |
| Audit chain | Authoritative for MCP events: every decidable frame, every verdict (including allows, including audit mode), `server/discover`, `subscriptions/listen`; client-supplied text clipped |
| Rug-pull detection | Fingerprints derived from proxied `tools/list` / `prompts/list` / `resources/list` / `server/discover` responses, plus periodic injected re-lists |
| Rate limits, approvals, plan adjudication | Verdict-side concerns; the server's planner asks over the channel |
| Kill switch + ladder ordering | The *decision* and its ordering (audit, banner, seal, finalize before any containment); rungs dispatched to the server as `actuate` commands |
| Egress loopback proxy | Harness mode only — see the placement decision below |
| GuardrailStatus / Kill tools | Injected into the proxied manifest **before** fingerprinting (so no drift), intercepted and answered by the harness. Kill keeps its non-authoritative routing: graceful stop unless policy arms containment |
| Telemetry (OTLP) | Verdict and frame metrics |

### Governed server, standalone mode (no harness)

Exactly today's windows-mcp-server wiring, built from the shared guardrails
packages this repo exports. The default policy is audit-only and **never
refuses** — a device that worked yesterday must not start denying calls after an
upgrade. Enforcement is what attaching a harness adds.

### Governed server, harness mode (`--harness` / control-channel env present)

| Stays in the server | Why |
|---|---|
| Host probes (posture, TPM attestation, dsregcmd, run context, WMI facts) | Physically host-bound; served as **signal-id evaluation** over the channel — never a generic remote-shell verb |
| Actuators (banner, isolate, kill processes, lock, shutdown, recording finalize, credential cleanup, egress OS enforcement) | Elevation, COM, and STA live here; the harness orders, the server executes and reports what the OS said |
| Credentials subsystem | The never-read invariant is strongest when no secret ever crosses a process boundary; the harness sees identifiers and lifecycle events only |
| Local host-events audit chain | Actuations, credential lifecycle, probe results — cross-anchored with the harness chain (each chain periodically records the other's head) |

Removed from the server in harness mode: enforce/rug-pull/telemetry middleware,
GuardrailStatus/Kill registration, the local egress proxy. The server never
refuses locally in harness mode — refusals are harness frames. The audit
middleware *stays* (two chains, defense in depth; the harness chain is
authoritative for MCP events, the server chain for host events).

## Egress proxy placement

**Harness-side in harness mode; server-side in standalone.**

1. The harness holds the live policy — layered ceilings and session-manifest
   origin lists update the allowlist in-process, with no config-push protocol.
2. Egress counters feed harness rate/kill decisions without crossing the
   channel.
3. The enforcement point leaves the process being contained: a rug-pulled
   server cannot reconfigure its own proxy.
4. Same host, so loopback-bind semantics (`requireLoopback`) are unchanged. The
   server-side firewall actuation (which needs elevation + COM) points at the
   port the harness announces in `hello.ack`.
5. Fail-closed: if the harness dies, its proxy dies with it, and under the
   scoped/global firewall tiers the server-side default-deny rules (state file
   + recovery on every start) block traffic rather than opening it.

The load-bearing egress invariants move with the package unmodified: the
allowlist is checked **before** any name resolution (a refused host must
produce no DNS query), forbidden-address vetting happens on resolved answers
with the dial going to the vetted address, and the listener asserts loopback at
bind.

## Policy layering (narrow-only)

Four layers, composed so that each may only **narrow** what the layers above
allow — never widen:

1. **Built-in risk map** — derived from tool annotations (`ReadOnlyHint`,
   `DestructiveHint`).
2. **Managed policy** — `AGENTWEAVE_MANAGED_POLICY` (env-pointed file; an
   invalid path refuses to start).
3. **User policy** — `--policy-config`.
4. **Session manifest** — `--session-manifest`: a bounded, expiring grant
   (`allow.tools`, `allow.resources.{apps,files,origins}`, `expires_after`,
   `idle_timeout`). Undeclared tool → typed refusal. Expiry → fail closed.

Narrowing means: severity monotone upward, allow-sets intersect, expiry takes
the minimum, mode may go audit→enforce but never enforce→audit. With no layers
present, behavior is the audit-only default. Full semantics land in
policy-config.md at Phase 5 (docs first, then code).

## Failure modes

| Failure | Detector | Behavior |
|---|---|---|
| Harness dies mid-session | Server: control-pipe EOF (+ stdin EOF) | Server cleans credentials, finalizes recording, seals its local chain, exits. Client sees transport close |
| Server dies mid-session | Harness: child exit / pipe EOF / heartbeat gap | Harness audits `server.lost`, seals, errors in-flight client calls, exits non-zero. Never keeps serving from cache |
| Channel wedged (open but silent) | Harness: heartbeat age > 3× interval | Heartbeat-gap trigger per policy (report-only unless armed) |
| Protocol ranges disjoint | `hello` negotiation | Harness refuses to start the session — never runs degraded |
| Egress port dead, harness alive | Firewall still standing (server state file + recovery) | Apps lose network = fail closed; harness restart re-announces the port |
| Invalid managed/user policy path | Harness load | Refuse to start |
| Session manifest expired / idle | Harness clock per frame | Typed refusal in the method's shape; session drains |

A session is born in one mode and dies in it: there is no runtime degradation
from harness mode to standalone.

## Module strategy

One Go module, `github.com/deploymenttheory/agentweave-harness`. The governed
server imports it permanently (standalone mode runs the full guardrails stack
from these packages). `wire/` is a stdlib-only *package* (enforced by an
import-discipline test) so it can be split into its own module later if
third-party servants appear. The harness never imports the server module.

The wire protocol is versioned independently of the module
(`wire.ProtocolVersion`, negotiated at `hello`); it freezes at harness v1.0.0.

## Repo layout (target)

```
cmd/agentweave-harness/   # cobra: run (spawn+proxy), check, policy {validate,check,explain}, verify, version
wire/                     # control-channel contract — envelope, message types, JSONL framing,
                          #   ProtocolVersion, typed refusal codes. STDLIB-ONLY.
guardrails/               # the packages extracted from windows-mcp-server, names unchanged:
                          #   signals, audit, hostmatch, policy, egress, enforce, watch, contain,
                          #   status, evidence, export, plan, telemetry
guardrails/manifest/      # bounded session manifest + layered-ceiling composition (Phase 5)
internal/proxy/           # MCP stdio frame pump, id remapping, request/tool injection
internal/control/         # pipe host, token auth, servant registry, correlation
internal/harness/         # orchestration: spawn child, lifecycle, RunProxy()
policy/examples/          # starting-point policy documents
docs/
```

## Phase plan

One branch and one PR per phase; both repos green after every phase.

| Phase | Repos | Delivers |
|---|---|---|
| 0 | harness | This scaffold + these ratified docs |
| 1 | both | Mechanical extraction of the 13 guardrails packages (tests and build tags move verbatim); server imports the tagged module; behavior byte-identical |
| 2 | harness | `wire/` + transparent proxy skeleton (pass-through, observe-only) |
| 3 | server | `--harness` servant mode: signal evaluation, actuate rungs, heartbeat/credential/anchor pushes; local stack unchanged |
| 4 | both | Harness enforcement on the proxy path; server sheds enforce/rug-pull/Status/Kill when `hello.ack` says `mode: enforce` |
| 5 | harness | Layered ceilings + bounded session manifests |
| 6 | both | Egress proxy relocates to the harness; server keeps OS enforcement as actuator rungs |
| 7 | both | Acceptance slice across the split on a disposable guest; docs migration; wire protocol freezes at v1.0.0 |

## Glossary

- **The harness** — always this product, agentweave-harness. Never anything
  else.
- **Acceptance rig** — windows-mcp-server's `internal/acceptance` test suite,
  which drives the shipped binary on a disposable weave/HCS guest. It is a test
  fixture, not this product, and docs on both sides use "rig" for it to keep
  the terms apart.
- **Servant** — the governed server's control-channel endpoint: evaluates
  declared signals, executes actuate rungs, pushes heartbeats and events.
- **Rung** — one step of the containment ladder, dispatched as an `actuate`
  command (banner, seal, finalize_recording, credential_cleanup, isolate,
  kill_procs, lock, shutdown, egress_apply, egress_suspend, egress_restore).
- **Decidable methods** — the five MCP methods the policy engine evaluates:
  `tools/call`, `resources/read`, `prompts/get`, `completion/complete`,
  `subscriptions/listen`.
- **Two-chain model** — the harness audit chain is authoritative for MCP
  events; the server's local chain for host events; each periodically anchors
  the other's head.
