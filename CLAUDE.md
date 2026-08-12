# CLAUDE.md

Guidance for AI coding agents working in this repository. These conventions are
load-bearing but not obvious from any single file.

## What this is

The adjudication harness for MCP servers and computer-use agents: a separate
process that wraps a governed MCP server (first:
[windows-mcp-server](https://github.com/deploymenttheory/windows-mcp-server)),
proxies its stdio MCP transport, and owns policy, audit, rug-pull detection and
containment from outside the process they govern. `docs/architecture.md` is the
ratified design; `docs/wire-protocol.md` is the control-channel contract (draft
until v1.0.0).

The `guardrails/` packages were extracted verbatim from windows-mcp-server's
`internal/guardrails` (Phase 1). Until the extraction completes, that server
imports these packages for its standalone mode — **changes here ship into the
server's in-process stack too.** The harness never imports the server module.

## Build, test, lint

```powershell
go build ./...
go vet ./...
go test ./... -count=1
$env:GOARCH='arm64'; go build ./...   # windows-tagged files assert (amd64 || arm64)
golangci-lint run --config=./.golangci.yml
```

CI runs **windows-latest and ubuntu-latest**: the decision core is untagged and
must stay runnable without a Windows host; the windows-tagged actuation files
(`contain`, `egress` OS enforcement, `signals` run-context) only exercise on the
Windows leg. Preserve that split.

Lint gates on **new issues only** (merge-base against main): the extraction
imported ~79 grandfathered issues with the code — see the comment in
`.golangci.yml` before "fixing" them casually; wrapcheck/err113/bodyclose fixes
change error shapes and request paths. Go files are LF via `.gitattributes`.
PR titles are conventional commits.

## The guardrails layer rule

`guardrails/` is split by lifecycle layer, and the import graph is **acyclic in
this order**:

| Package | Holds | Depends on |
|---|---|---|
| `signals` | signal vocabulary, probes interfaces, `Registry`, checks, `Decision` | — |
| `audit` | hash chain, destination, `VerifyChain` | — |
| `hostmatch` | egress allowlist compiler, wildcard matcher, forbidden ranges | — |
| `evidence` | bundle seal/sign/verify | — |
| `plan` | plan compile/validate/derive | — |
| `telemetry` | OTLP metrics/traces | — |
| `policy` | document schema, signal cache, engine, verdict | `signals`, `hostmatch` |
| `manifest` | session manifest, layered narrow-only composition, `MaxVerdict` | `policy`, `hostmatch`, `wire` |
| `egress` | loopback proxy, counters, `Enforcer`, OS enforcement | `hostmatch`, `contain` |
| `enforce` | the MCP middleware, refusal shapes | `policy`, `audit` |
| `watch` | heartbeat, rug-pull, monitor | `audit`, `signals` |
| `contain` | kill switch, ladder, `SystemActuator`, firewall | `audit`, `signals` |
| `status` | status endpoint, `GuardrailStatus` + `Kill` tools | `signals`, `contain` |

Two properties to preserve:

- **`signals`, `audit`, `hostmatch` are leaves.** Recording must never be
  contingent on the thing being recorded; the signal catalogue stays evaluable
  on its own; `hostmatch` must be importable by `policy` without dragging the
  proxy in.
- **`policy` has no MCP dependency.** The decision is testable against fake
  signals and a fake tool index, with no transport. Anything MCP-shaped belongs
  in `enforce` (or, post-extraction, the frame-level proxy path).

## Invariants that are easy to break

- **The default must never refuse.** `policy_default.json` applies when no
  document is given; `TestDefaultPolicyIsAuditOnly` pins it (and pins egress
  default-off). `mode: audit` *caps* severity rather than skipping evaluation —
  the recorded `intended` verdict is what makes audit mode worth running.
- **Never merge two layers' rules into one document.** The engine attributes
  each required signal to its single most specific matching rule (ties: last
  wins), so a merged document lets one layer's weaker rule shadow another's
  stricter one — a widening. Layered decisions are strictest-of-per-layer
  verdicts (`manifest.Compose` keeps `RuleLayers` separate, `MaxVerdict` takes
  the max; `TestLowerLayersOnlyNarrow` is the property pin, and it is the test
  that caught this).
- **Transparency is never conditional on containment.** Every verdict is
  audited, including allows, including audit mode; the decision entry is written
  before any trip.
- **A report-only trip must not end the in-flight monitor**
  (`TestMonitorReportOnlyTripKeepsMonitoring`).
- **The kill ladder's ordering is deliberate** (`contain/killaction.go`): audit,
  banner, **seal** before any containment. Don't reorder.
- **Refuse in the shape the method requires** (`enforce/enforce.go`): `IsError`
  result for `tools/call`; JSON-RPC error for the other four decidable methods.
- **Egress: the allowlist is checked before the name is resolved** (a refused
  host must produce no DNS query); forbidden addresses are vetted on resolved
  answers and the dial goes to the vetted address; the listener asserts loopback
  at bind. Scoped firewall rules are protocol-ANY (QUIC is UDP); missing
  elevation for a policy naming applications is fatal, not degraded; global
  block writes its state file before any mutation and `Suspend()` never
  restores.
- **The signal cache starts unread, not passing**, and `Refresh` never reports
  a failing signal as an error (a `VerifyFunc` error fires a kill trigger,
  escalating every failure past its assigned severity).
- **Secrets** for tier-2 signals come from environment variables, never flags or
  the policy document. No secret value, length or character count ever appears
  in any chain, frame, or log — coarse bands only.

## Wire and naming rules (from Phase 2 on)

- `wire/` is **stdlib-only** — enforced by test. It can become its own module
  later; don't add dependencies to it.
- The control channel has **no generic exec verb**: signals are evaluated by
  declared id, actuation is a fixed rung vocabulary. Unknown rung → refuse and
  audit, never guess.
- stdout is reserved for the proxied MCP stream; harness diagnostics go to
  stderr.
- "The harness" is this product. windows-mcp-server's `internal/acceptance`
  test suite is the "acceptance rig" — never call it the harness.
