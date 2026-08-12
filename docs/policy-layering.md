# Layered policy and session manifests

This document is the ratified semantics for the harness's layered policy
composition and the bounded session manifest. It was written before the code
that implements it, and the code is held to it. The base policy-document schema
(signals, rules, rate limits, egress, transparency, …) is documented alongside
in [`policy-config.md`](policy-config.md); this one covers what the harness
adds on top — the four layers, the session manifest, and argument constraints.

## The four layers

A session's effective policy is composed from up to four layers. Every layer
below the first is optional; with none present, behavior is the audit-only
default and nothing is refused.

| # | Layer | Source | Who writes it |
|---|---|---|---|
| 1 | Built-in risk vocabulary | compiled in | this repo |
| 2 | Managed policy | `AGENTWEAVE_MANAGED_POLICY` (env-pointed file) | fleet operator / MDM |
| 3 | User policy | `--policy-config` | device operator |
| 4 | Session manifest | `--session-manifest` | whoever launches the session |

**Layer 1** is not a document. It is the annotation vocabulary the engine
already evaluates (`read-only`, `destructive`, `open-world` — taken from the
tool annotations the server advertises and fingerprinted against drift) plus
the embedded audit-only default that applies when no other layer is given. Two
of its readings are load-bearing: a tool **absent from the observed index is
treated as maximum risk**, never as "no annotations"; and the default document
**never refuses** (`TestDefaultPolicyIsAuditOnly`).

**Layers 2 and 3** are ordinary policy documents (same schema, same
`version: 1`). **Layer 4** is the session manifest, a different and much
smaller schema (below).

## Narrowing: the only direction

Each layer may only *narrow* what the layers above it allow. Concretely, the
composed policy is built by folding layer 3 onto layer 2 with these rules —
"upper" is the earlier layer, "lower" the later:

| Field | Rule | Why this is narrowing |
|---|---|---|
| `mode` | `enforce` wins: audit→enforce only, never enforce→audit; the composed mode governs **every** layer's rules | enforcement can be added, never removed; promoting a layer's severity is narrowing |
| `rules`, `signals`, `rate_limits` | **never merged into one document.** Each rule-bearing layer keeps its own document (promoted to the composed mode) and is evaluated by its own engine; the strictest verdict wins | the engine attributes each required signal to its single most specific matching rule (ties: last wins), so merging two layers' rules would let one layer's *weaker* rule shadow another layer's *stricter* rule for the same signal — a widening. (Found by this phase's own property test; strictest-of-per-layer-verdicts is narrow-only by construction.) Rate-limit windows are per layer, so entries only accumulate and `max` values are never compared across layers |
| `enforce_https` | OR | plaintext can be forbidden, never re-permitted |
| `require_plan` | union of selectors | consumed as a set with no attribution to shadow; more calls can be made to require a plan, never fewer |
| `kill.triggers` / `kill.actions` | OR per switch; `kill_procs` union; `shutdown_delay` minimum of the values set | arming more containment restricts the agent, never the reverse |
| `egress` | if only one layer enables it, that layer's config; if both, **allow-lists intersect** and ports intersect. A wildcard survives the intersection only opposite a wildcard at or above it — an exact name on the other side covers one host, never a subtree | the composed reachable set can only shrink |

**The managed layer carries restrictions, not operational configuration.** A
managed document that sets `transparency`, `telemetry`, `approvals`,
`credentials` or `inflight` refuses to start: those blocks configure where this
device's chains, spans and approvals go, which belongs to the device operator
(layer 3). This keeps the composition auditable — everything a managed layer
can do is something an agent could only experience as "less".

**An invalid managed-policy path refuses to start.** `AGENTWEAVE_MANAGED_POLICY`
pointing at a missing or unparsable file is a hard error, not a fallback to
unmanaged: silently running wider than the fleet operator intended is the
failure being prevented. (An unset variable simply means there is no layer 2.)
The same applies to `--policy-config` and `--session-manifest`: a named layer
that cannot be loaded never degrades to "no layer".

## The session manifest

A bounded, expiring grant for one session:

```json
{
  "version": 1,
  "allow": {
    "tools": ["Snapshot", "Click", "Type"],
    "resources": {
      "apps": ["notepad", "excel"],
      "files": ["C:\\work\\reports"],
      "origins": ["intranet.example.com"]
    }
  },
  "expires_after": "30m",
  "idle_timeout": "5m"
}
```

Semantics:

- **`expires_after` is required.** A manifest exists to bound a session; one
  with no expiry is not bounded and is refused at load. The clock starts when
  the session starts, is checked per frame in the harness, and when it runs
  out every decidable request gets a typed refusal
  (`session_expired`) in the method's correct shape — the session drains, it
  is not killed. `idle_timeout` is optional; it refuses with
  `session_idle_timeout` when no decidable request has been *allowed* for that
  long. Refused requests do not refresh the idle clock — a denied call must
  not keep a session alive.
- **`allow.tools`**: a `tools/call` naming a tool outside the list is refused
  with `permission_denied`. An *absent* `allow.tools` means the manifest does
  not restrict tools; an explicitly **empty list means no tools** — absence
  and emptiness are different statements.
- **`allow.resources.files` / `origins`**: a `resources/read` whose URI falls
  outside every listed file prefix and origin is refused with
  `bounded_resource_outside_manifest`. Same absent-vs-empty rule.
- **`allow.resources.apps`** names the applications the session may launch.
  It is enforced at the argument level (the `App` tool's `name`), so its
  enforcement lands with argument constraints; the schema carries it from the
  start so manifests do not change shape later.
- **`origins` also feed the egress allow-list**: the composed egress policy
  intersects with the manifest's origins, so a bounded session's network
  reach shrinks to match what it may read. (The enforcement point moves
  harness-side at Phase 6; the composition point exists now.)
- A manifest can only narrow, like every layer: it cannot name a tool into
  existence, raise a rate limit, or turn enforcement off. There is no
  mechanism to widen a manifest mid-session — a session's grant is fixed at
  birth and can only expire (see `docs/scope.md`).

## Typed refusal codes

Defined in `wire/` (stdlib-only, importable by both enforcement stacks):

| Code | Meaning |
|---|---|
| `permission_denied` | the manifest's `allow.tools` does not include the tool |
| `bounded_resource_outside_manifest` | the resource read falls outside `allow.resources` |
| `session_expired` | `expires_after` has elapsed |
| `session_idle_timeout` | `idle_timeout` elapsed with no allowed decidable request |

A typed refusal is surfaced in the method's correct shape — an `IsError`
result for `tools/call`, a JSON-RPC error for the data-egress methods — with
the code carried in the error's `data.code` member (JSON-RPC) or the result
text (`tools/call`, which has no data member). Policy-rule denials (a failing
required signal) keep their existing reason text; the typed codes name the
*manifest and session-lifetime* refusals, which have no signal to explain them.

## Argument-level constraints

Rules gain an optional `constraints` block, evaluated against the call's
arguments after the match and before the verdict:

```json
{
  "name": "bounded-typing",
  "match": {"tool": "Type"},
  "require": [],
  "constraints": {"text": {"max_length": 4096}},
  "on_fail": "deny"
}
```

Per argument: `min` / `max` (numbers), `max_length` (strings, in bytes),
`pattern` (regular expression, standard unanchored matching — write `^…$` to
anchor). **Patterns are RE2** — Go's `regexp` — which cannot backtrack, so
evaluation cost is linear in the input (already bounded by the 256 KiB frame
cap) and a policy author cannot write a pattern that stalls the decision
path; a backreference does not compile, and validation refuses it
(`TestArgumentPatternsAreRE2Bounded` pins this). A constraint on an argument
the call does not carry fails the rule (absent is not compliant), as does a
value of the wrong type. Two more rules keep this safe:

- **A subject with no argument context skips constraints entirely.** A real
  `tools/call` always has argument context (an omitted `arguments` object is
  an empty set, in which every constrained argument is absent and fails);
  plan-time and startup subjects have none, so constraints are spent where
  the arguments actually are — at call time — rather than failing every plan
  step that has no arguments to check.
- **A constraint failure's detail names the argument and the bound, never the
  value.** Argument values are the caller's content; they stay out of the
  audit chain here for the same reason tool arguments are digested, not
  recorded.

## What composition never does

- It never touches the embedded default: `TestDefaultPolicyIsAuditOnly` holds
  with all four layers absent.
- It never merges operational blocks from the managed layer (refused at load
  instead).
- It never compares incomparable rate limits (union only).
- It never widens: `TestLowerLayersOnlyNarrow` is a property test asserting
  that for any composed policy and any subject, the composed verdict's
  severity is ≥ every individual layer's verdict severity.
