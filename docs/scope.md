# Scope: what this harness does not do

An honest scope statement, in the style cua's permission-policy docs model:
naming what a control does *not* cover is part of making the claim about what
it does cover trustworthy.

## Not provided

- **No protection from a compromised host.** The harness and the governed
  server run on the same machine as the same user. The boundary is a process
  boundary, not a privilege or machine boundary: it defeats a misbehaving or
  rug-pulled *server*, not an attacker with the user's session. For a machine
  boundary, run the pair inside a disposable VM (see windows-mcp-server's
  vm-isolation note).
- **No caller authentication.** The harness trusts its stdin/stdout peer to be
  the MCP client the operator launched it under. It does not authenticate the
  client, and it must never listen on a network socket for MCP traffic — the
  stdio-only posture is inherited from the governed server and kept.
- **No response inspection.** Policy decides *requests* (the five decidable
  methods). Tool *results* flow back unexamined; data-loss inspection of
  responses is out of scope (egress control constrains where bytes can go
  instead).
- **No budget/spend accounting.** Rate limits are counts per window, not
  cost-denominated budgets. (Roadmap.)
- **No trajectory recording or replay.** The audit chain records digests and
  verdicts, not replayable action streams. (Roadmap.)
- **No privilege escalation ladder for the agent.** There is no mechanism for
  the governed session to request a widened grant mid-run; a session's
  manifest is fixed at birth and can only expire. (Roadmap.)
- **No VM lifecycle management.** The harness wraps a process, not a guest.
  Snapshot/fork/dispose of the environment belongs to the tooling around the
  harness.
- **No non-MCP agents yet.** The wrapping contract is MCP stdio. Wrapping
  other computer-use agent protocols is a design goal, not a shipped feature.

## Never sent, never recorded

These are invariants, pinned by tests as the phases land, not aspirations:

- **No secret values.** Credential *identifiers* and lifecycle events cross
  the control channel; plaintext secrets never do, in either direction. The
  never-read invariant lives entirely inside the governed server. The harness
  also never records a secret *length or character count* — only the coarse
  bands the server already exposes.
- **No generic execution verb.** The control channel has no shell/exec
  message. Signals are evaluated by declared id against the server's registry;
  an actuation is one of a fixed set of rungs. A harness compromise must not
  become remote code execution on the host, by construction of the vocabulary.
- **No raw tool arguments in the audit chain.** Arguments are digested, never
  stored raw — the chain must be reviewable without becoming a data store of
  everything the agent typed.
- **No unbounded client-controlled chain growth.** Client-supplied text in
  audited events is clipped; per-request egress events aggregate into periodic
  summaries rather than one chain entry per request.
- **No network listener for MCP.** stdio only, both processes. The only
  sockets the harness opens are the loopback egress proxy (bind asserted
  loopback at listen) and any operator-configured outbound reporting
  (approvals webhook, OTLP, evidence export).
