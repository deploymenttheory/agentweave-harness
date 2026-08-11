# Roadmap

Ideas deliberately deferred from the initial build, with their provenance.
The initial scope is: parity with windows-mcp-server's in-process guardrails,
plus layered policy ceilings and bounded session manifests. Everything below
waits until that is shipped and pinned.

## Deferred, in rough priority order

### Budget veto callbacks
A spend-denominated analogue of rate limits: accumulate cost from usage
signals, veto continuation when the budget is exhausted. cua ships this as
`BudgetManagerCallback` in its agent-loop callback chain. In harness terms it
is a verdict source fed by token/cost telemetry rather than call counts.

### Trajectory recording and replay
Per-action turn folders (before/after state, screenshots, action record),
renderable to video and deterministically replayable. cua's driver records
`turn-NNNNN/` folders and exposes `replay_trajectory`. The harness sits on the
MCP wire, so it could standardize a portable trajectory format across governed
servers — windows-mcp-server's Recording/CaptureEvidence tools already produce
most of the raw material.

### Escalation ladder with machine-readable reasons
cua's capture-scope model: a session declares a scope, widening it requires an
explicit escalation call carrying a ladder-exhaustion reason, the grant is
audited and irreversible, and a strict scope can never escalate. The harness
version: a session manifest that can be *extended* only by an out-of-band
operator action carrying a recorded reason — the harness owns the grant, the
server (or agent) owns the request.

### Content-free telemetry with a published never-sent list
cua documents exactly which fields its product telemetry never transmits and
reduces payloads to shape categories and size buckets. The harness's OTLP
metrics should adopt the same discipline and publish the list in scope.md.

### Callback/hook vocabulary for in-loop guardrails
cua's `AsyncCallbackHandler` shows that a small hook set (run-continue veto,
message rewrite, usage report) is enough to express budget kills, PII
scrubbing, image retention and schema repair as composable, ordered hooks. If
the harness ever hosts an agent loop (not just a server), this is the
extension surface to copy.

### Wrapping non-MCP computer-use agents
The harness contract is currently MCP stdio. Generalizing the proxy seam so
the same policy/audit/containment core can wrap other agent protocols is the
long-term reason the repo is named agentweave-harness rather than
mcp-harness.

### VM lifecycle integration
Snapshot → copy-on-write fork → dispose, as cua's sandbox SDK and Lume do for
guests. Out of scope for the harness itself, but the acceptance rig already
runs the pair on a disposable HCS guest; a thin integration (harness asks the
rig's weave layer for a fresh guest) would make contained-session forensics
and repeatable incident drills cheap.

## Explicitly rejected

- **A score.** No self-graded compliance or security number. Verdicts,
  chains, and suite results only — the governed server's history with
  self-scoring is the cautionary tale.
- **An HTTP MCP listener.** The stdio-only posture is load-bearing on both
  sides of the proxy.
