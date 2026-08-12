// Package inject adds the harness's own tools to the proxied manifest and
// answers their calls, for a session where the governed server has shed its
// GuardrailStatus/Kill tools (enforce mode). The tools are defined here as raw
// JSON because the harness answers them itself — it never hands them to the
// server's SDK — and the client must see them inside the same tools/list the
// rug-pull baseline is taken from.
//
// Two tools:
//   - GuardrailStatus (read-only): reports the harness's posture for the
//     session — mode, whether it is enforcing, the bound tool count.
//   - Kill (destructive): ends the session. Non-authoritative, exactly like the
//     server's own Kill: it routes to a graceful stop, never to containment an
//     operator did not arm.
package inject

import (
	"encoding/json"
	"strings"

	"github.com/deploymenttheory/agentweave-harness/internal/proxy"
)

// The injected tool names. A tools/call for either is answered here, not
// forwarded to the server.
const (
	ToolGuardrailStatus = "GuardrailStatus"
	ToolKill            = "Kill"
)

// StatusProvider reports the harness posture GuardrailStatus returns. It is a
// function so the injector holds no engine reference: the harness supplies a
// closure over whatever it wants surfaced.
type StatusProvider func() Status

// Status is the harness-side posture the GuardrailStatus tool reports. It is
// deliberately small and carries no device identifiers — the harness is not
// the desktop, and an agent-facing tool must not become a fingerprinting
// side channel.
type Status struct {
	Mode       string `json:"mode"`
	Enforcing  bool   `json:"enforcing"`
	Bounded    bool   `json:"bounded"`
	RuleLayers int    `json:"rule_layers"`
}

// Injector implements proxy.ToolInjector and answers the injected tools' calls
// via Answer, which a wrapping interceptor consults before the policy decision.
type Injector struct {
	status StatusProvider
	stop   func(reason string)
}

// New builds the injector. status reports posture for GuardrailStatus; stop
// ends the session for Kill (a graceful stop the harness supplies).
func New(status StatusProvider, stop func(reason string)) *Injector {
	return &Injector{status: status, stop: stop}
}

// Tools implements proxy.ToolInjector: the two tool definitions appended to
// every tools/list result.
func (i *Injector) Tools() []json.RawMessage {
	return []json.RawMessage{
		json.RawMessage(`{` +
			`"name":"GuardrailStatus",` +
			`"description":"Report the current guardrail posture enforced by the harness for this session: mode, whether it is enforcing, whether the session is bounded by a manifest, and the served tool count. Read-only.",` +
			`"annotations":{"title":"Guardrail status","readOnlyHint":true},` +
			`"inputSchema":{"type":"object"}}`),
		json.RawMessage(`{` +
			`"name":"Kill",` +
			`"description":"Immediately and cleanly stop this MCP session. Use to abort automation. This is the agent-facing convenience trigger; authoritative kill triggers are independent of the agent.",` +
			`"annotations":{"title":"Kill session","readOnlyHint":false,"destructiveHint":true},` +
			`"inputSchema":{"type":"object","properties":{"reason":{"type":"string","description":"Why the session is being stopped."}}}}`),
	}
}

// Answers reports whether the named tool is one this injector answers, so a
// wrapping interceptor can route its call here instead of to the server.
func (i *Injector) Answers(tool string) bool {
	return tool == ToolGuardrailStatus || tool == ToolKill
}

// Answer produces the tool result text for an injected tool call. The bool
// reports whether this injector owns the tool; false means "not mine, forward
// it". args is the raw params.arguments, used only by Kill.
func (i *Injector) Answer(tool string, args json.RawMessage) (string, bool) {
	switch tool {
	case ToolGuardrailStatus:
		s := Status{}
		if i.status != nil {
			s = i.status()
		}
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return "guardrail status unavailable", true
		}
		return string(b), true
	case ToolKill:
		reason := "kill requested via MCP Kill tool"
		var a struct {
			Reason string `json:"reason"`
		}
		if len(args) > 0 {
			_ = json.Unmarshal(args, &a)
			if strings.TrimSpace(a.Reason) != "" {
				reason = "MCP Kill tool: " + a.Reason
			}
		}
		if i.stop != nil {
			i.stop(reason)
		}
		return "Session stopping: " + reason, true
	default:
		return "", false
	}
}

// Ensure Injector satisfies the proxy seam.
var _ proxy.ToolInjector = (*Injector)(nil)
