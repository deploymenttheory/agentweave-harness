// Package wire is the control-channel contract between the harness and a
// governed server's servant: envelope shape, message-type vocabulary, payload
// schemas and the JSONL framing. It is the one package both sides must agree
// on, so it is deliberately STDLIB-ONLY (pinned by TestWireIsStdlibOnly) and
// versioned independently of the module: ProtocolVersion moves only when the
// vocabulary changes shape, and hello/hello.ack negotiate a version both sides
// speak. docs/wire-protocol.md is the prose form of this contract.
//
// Two properties of the vocabulary are load-bearing, per docs/scope.md:
// there is no generic execution verb (signals are evaluated by declared id,
// actuation is the fixed rung set below), and no message carries a secret
// value — credential events name identifiers only.
package wire

import "encoding/json"

// Protocol versions this package implements. A session speaks exactly one
// version, negotiated in hello (server sends its [min,max]) and fixed by
// hello.ack. No overlap between the two sides' ranges means the harness
// refuses to start the session — never run degraded.
const (
	MinProtocolVersion = 1
	MaxProtocolVersion = 1
)

// Message types flowing up, server → harness.
const (
	// TypeHello is the first message on the channel and must carry the
	// bootstrap token; anything else (or a wrong token) kills the child.
	TypeHello = "hello"
	// TypeSignalResult answers a signal.evaluate request.
	TypeSignalResult = "signal.result"
	// TypePosturePush is an unsolicited batch of signal results after a local
	// cache refresh.
	TypePosturePush = "posture.push"
	// TypeHeartbeat reports desktop-engine liveness — the one liveness fact
	// the proxy cannot infer from MCP frames.
	TypeHeartbeat = "heartbeat"
	// TypeCredentialEvent reports credential lifecycle transitions.
	// Identifiers only, never values, lengths or character counts.
	TypeCredentialEvent = "credential.event" //nolint:gosec // G101: message-type name, not a credential
	// TypeEgressState reports OS-enforcement actuator state.
	TypeEgressState = "egress.state"
	// TypeActuateResult answers an actuate command with what the OS reported.
	TypeActuateResult = "actuate.result"
	// TypeAuditAnchor carries a chain head so each side can pin the other's
	// chain. Sent in both directions.
	TypeAuditAnchor = "audit.anchor"
	// TypePlanEvaluate asks the harness for verdicts on a plan's subjects.
	TypePlanEvaluate = "plan.evaluate"
)

// Message types flowing down, harness → server.
const (
	// TypeHelloAck fixes the negotiated version and delivers the effective
	// config the server must apply before building its tool surface.
	TypeHelloAck = "hello.ack"
	// TypeSignalEvaluate requests evaluation of declared signal ids. There is
	// deliberately no verb that names a program or a script.
	TypeSignalEvaluate = "signal.evaluate"
	// TypeActuate commands one containment rung.
	TypeActuate = "actuate"
	// TypePlanVerdict answers plan.evaluate.
	TypePlanVerdict = "plan.verdict"
	// TypeConfigUpdate delivers a mid-session effective-config change.
	TypeConfigUpdate = "config.update"
	// TypeShutdown asks the server to end the session in an orderly way.
	TypeShutdown = "shutdown"
)

// Actuation rungs. The vocabulary is closed: a rung not in this list is
// refused and audited by the servant, never guessed at. Transparency rungs
// (banner, seal, finalize_recording) are always dispatched before containment
// rungs (isolate, kill_procs, lock, shutdown) — the ladder's ordering is the
// harness's job; execution and honest reporting are the servant's.
const (
	RungBanner            = "banner"
	RungSeal              = "seal"
	RungFinalizeRecording = "finalize_recording"
	RungCredentialCleanup = "credential_cleanup" //nolint:gosec // G101: rung name, not a credential
	RungIsolate           = "isolate"
	RungKillProcs         = "kill_procs"
	RungLock              = "lock"
	RungShutdown          = "shutdown"
	RungEgressApply       = "egress_apply"
	RungEgressSuspend     = "egress_suspend"
	RungEgressRestore     = "egress_restore"
)

// Envelope is the framing every message shares. ID is set on requests; Re
// correlates a response to its request's ID; notifications carry neither.
type Envelope struct {
	V       int             `json:"v"`
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Re      string          `json:"re,omitempty"`
	TS      string          `json:"ts"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Hello is the server's opening message.
type Hello struct {
	// ProtoMin and ProtoMax bound the protocol versions the server speaks.
	ProtoMin int `json:"proto_min"`
	ProtoMax int `json:"proto_max"`
	// ServerVersion is the governed server's build version, for the audit
	// record and version-skew diagnostics.
	ServerVersion string `json:"server_version"`
	// SessionStamp identifies the session for correlation across both audit
	// chains.
	SessionStamp string `json:"session_stamp"`
	// Token is the bootstrap secret from AGENTWEAVE_CONTROL_TOKEN. The
	// harness compares it in constant time and kills the child on mismatch.
	Token string `json:"token"`
	// Capabilities declare what this servant can do, so the harness never has
	// to guess and a policy needing more than the servant offers can refuse
	// the session at handshake.
	Capabilities Capabilities `json:"capabilities"`
}

// Capabilities is the servant's declared surface.
type Capabilities struct {
	// Signals are the declared signal ids the servant can evaluate.
	Signals []string `json:"signals,omitempty"`
	// Actuators are the rungs the servant can execute.
	Actuators []string `json:"actuators,omitempty"`
	// Elevated reports whether the process holds administrative rights —
	// a policy demanding OS enforcement of a non-elevated servant refuses at
	// handshake rather than serving a weaker posture.
	Elevated bool `json:"elevated"`
	// RunContext names the process's Windows security context (session,
	// integrity), as the run-context signal reports it.
	RunContext string `json:"run_context,omitempty"`
}

// HelloAck fixes the session's protocol version and delivers config.
type HelloAck struct {
	Proto int `json:"proto"`
	// Mode is "enforce" or "observe". Observe means the harness proxies and
	// records but synthesizes no refusals — the server keeps its local stack.
	Mode string `json:"mode"`
	// EffectiveConfig must be applied before the tool surface is built.
	EffectiveConfig EffectiveConfig `json:"effective_config"`
}

// Modes carried by HelloAck.Mode.
const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
)

// EffectiveConfig is the policy-derived configuration the server applies
// locally. It carries settings, never rules: the rules stay in the harness.
type EffectiveConfig struct {
	EnforceHTTPS   bool     `json:"enforce_https,omitempty"`
	ProtectedPaths []string `json:"protected_paths,omitempty"`
	Banner         bool     `json:"banner,omitempty"`
	// EgressProxyPort, when non-zero, names the harness-side loopback proxy
	// port; the server then runs no proxy of its own and points its dialers
	// and OS enforcement at this port.
	EgressProxyPort int `json:"egress_proxy_port,omitempty"`
	// EgressProxyExecutable is the full image path of the harness process
	// serving that proxy, for the firewall allow rule under a global outbound
	// block: the rule must name the process actually dialing out, or it is a
	// grant nothing uses. Host-local by nature — both processes share the
	// machine.
	EgressProxyExecutable string `json:"egress_proxy_executable,omitempty"`
	// HeartbeatIntervalMS is how often the servant pushes heartbeats.
	HeartbeatIntervalMS int `json:"heartbeat_interval_ms,omitempty"`
}

// SignalEvaluate requests evaluation of declared signal ids, optionally with
// per-signal arguments (e.g. a hostname for the may-run signal).
type SignalEvaluate struct {
	IDs  []string          `json:"ids"`
	Args map[string]string `json:"args,omitempty"`
}

// SignalResult carries evaluation outcomes. The result shape mirrors
// guardrails/signals.Result; it is declared loosely here so wire stays
// stdlib-only and version-tolerant.
type SignalResult struct {
	Results []json.RawMessage `json:"results"`
}

// Heartbeat reports liveness of the parts the proxy cannot see.
type Heartbeat struct {
	Seq           uint64 `json:"seq"`
	DesktopAlive  bool   `json:"desktop_alive"`
	RecorderState string `json:"recorder_state,omitempty"`
}

// CredentialEvent reports a lifecycle transition. IDs are credential names —
// never values, and never counts derived from values.
type CredentialEvent struct {
	Kind string   `json:"kind"`
	IDs  []string `json:"ids,omitempty"`
}

// Credential event kinds.
const (
	CredentialInstalled   = "installed"
	CredentialRemoved     = "removed"
	CredentialInjected    = "injected"
	CredentialCleanupDone = "cleanup_done"
)

// EgressState reports the OS-enforcement side of egress.
type EgressState struct {
	Tier         string `json:"tier"`
	RulesPresent bool   `json:"rules_present"`
	Recovered    bool   `json:"recovered"`
}

// Actuate commands one rung of the ladder.
type Actuate struct {
	Rung string `json:"rung"`
	// Params carries rung-specific parameters (e.g. egress_apply's port and
	// application list), schema owned by the rung.
	Params json.RawMessage `json:"params,omitempty"`
}

// EgressApplyParams is the schema for the egress_apply rung's Params: the OS
// firewall enforcement the harness asks the governed server to install on its
// behalf, pointed at the harness-side proxy. It exists because the composed
// egress policy lives harness-side while the actuation — firewall rules,
// WinINET — must happen on the host. Suspend and restore carry no params.
type EgressApplyParams struct {
	// ProxyPort is the harness proxy's loopback port the blocked applications
	// must still be able to reach.
	ProxyPort int `json:"proxy_port"`
	// ProxyExecutable is the harness image, for the global-block allow rule.
	ProxyExecutable string `json:"proxy_executable,omitempty"`
	// Applications are full image paths to block outbound (scoped tier).
	Applications []string `json:"applications,omitempty"`
	// BlockAllOutbound flips the machine's default outbound action (global tier).
	BlockAllOutbound bool `json:"block_all_outbound,omitempty"`
	// AllowPorts bounds the proxy's own allow rule under a global block.
	AllowPorts []int `json:"allow_ports,omitempty"`
	// SetSystemProxy points this user's WinINET settings at the proxy.
	SetSystemProxy bool `json:"set_system_proxy,omitempty"`
}

// ActuateResult reports what actually happened, in the servant's
// skip-and-audit idiom: a rung the process cannot perform is reported
// skipped with a reason, not silently dropped and not faked.
type ActuateResult struct {
	Rung string `json:"rung"`
	OK   bool   `json:"ok"`
	// Observed is what the OS reported back, per observation.
	Observed []string `json:"observed,omitempty"`
	// SkippedReason is set when the rung was not attempted (e.g. not
	// elevated).
	SkippedReason string `json:"skipped_reason,omitempty"`
}

// AuditAnchor carries one side's chain head so the other side's chain can
// pin it. Cross-anchoring is what makes the two-chain model tamper-evident
// as a pair.
type AuditAnchor struct {
	Seq  uint64 `json:"seq"`
	Head string `json:"head"`
}

// Shutdown asks the server to end the session.
type Shutdown struct {
	Reason   string `json:"reason"`
	Graceful bool   `json:"graceful"`
}
