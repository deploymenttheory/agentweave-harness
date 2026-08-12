// Package enforce is the harness's refusal seam: it sits on the proxy's
// interception hook, decides each decidable client request against the policy
// engine, and — on a denial — synthesizes the refusal in the exact shape the
// method requires, so the governed server never sees a request the harness
// refused.
//
// This is the enforcing half of moving adjudication out of the server. The
// verdict is reached in the harness process, on the wire, using the tool index
// the observer built from the manifest; the server is not consulted and cannot
// override it. Two shape rules are load-bearing and match the in-process
// enforcer exactly: a refused tools/call is an IsError result (a JSON-RPC
// success frame carrying isError), so the model can read the reason and adapt;
// a refused resources/read, prompts/get, completion/complete or
// subscriptions/listen is a JSON-RPC error, because those methods have no
// IsError envelope and a CallToolResult would be the wrong shape on the wire.
package enforce

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// The decidable MCP methods — the five the policy engine reasons about.
const (
	methodCallTool     = "tools/call"
	methodReadResource = "resources/read"
	methodGetPrompt    = "prompts/get"
	methodComplete     = "completion/complete"
	methodListen       = "subscriptions/listen"
)

// codeInvalidRequest is the JSON-RPC error code for a policy refusal on a
// non-tool method. InvalidRequest (-32600), not an MCP-specific code: protocol
// revision 2026-07-28 reserves -32020..-32099 for the specification, so a
// policy refusal has no business minting a code in that range — the same choice
// the in-process enforcer makes.
const codeInvalidRequest = -32600

// Decider reaches a verdict on one decidable request. Returning allow=true
// forwards it; allow=false refuses with the given reason. It is the policy
// engine in production and a fake in tests.
type Decider interface {
	Decide(ctx context.Context, method string, params json.RawMessage) (allow bool, reason string)
}

// DenyAll refuses every decidable request with a fixed reason. It is the
// fail-closed decider installed while the policy engine is still initializing
// (before the servant has connected and its signals are reachable): an
// operator who configured enforcement must not get an unadjudicated window,
// so decidable calls are refused until the real decider is ready. Non-decidable
// traffic — initialize, tools/list, notifications — is unaffected, because the
// Interceptor never consults the decider for those.
type DenyAll struct{ Reason string }

// Decide always refuses.
func (d DenyAll) Decide(context.Context, string, json.RawMessage) (bool, string) {
	return false, d.Reason
}

// Interceptor implements proxy.Interceptor over a Decider. It only ever refuses
// the five decidable request methods; everything else it forwards untouched by
// returning nil.
type Interceptor struct {
	decider Decider
	logger  *slog.Logger
}

// NewInterceptor builds the refusal seam.
func NewInterceptor(d Decider, logger *slog.Logger) *Interceptor {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Interceptor{decider: d, logger: logger}
}

type requestFrame struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// Intercept decides a client frame. A decidable request with a readable id is
// put to the decider; a denial is answered in the method's shape and the
// request is dropped. Everything else returns nil (forward).
func (i *Interceptor) Intercept(raw []byte) []byte {
	var f requestFrame
	if json.Unmarshal(raw, &f) != nil {
		return nil
	}
	if !decidable(f.Method) || len(f.ID) == 0 || string(f.ID) == "null" {
		return nil
	}
	allow, reason := i.decider.Decide(context.Background(), f.Method, f.Params)
	if allow {
		return nil
	}
	frame, err := refusalFrame(f.Method, f.ID, reason)
	if err != nil {
		// A refusal we cannot serialize must still not forward: fail closed with
		// a generic JSON-RPC error rather than letting the request through.
		i.logger.Error("enforce: could not synthesize refusal; failing closed", "err", err)
		return errorFrame(f.ID, "blocked by policy")
	}
	i.logger.Info("enforce: refused", "method", f.Method, "reason", reason)
	return frame
}

func decidable(method string) bool {
	switch method {
	case methodCallTool, methodReadResource, methodGetPrompt, methodComplete, methodListen:
		return true
	default:
		return false
	}
}

// refusalFrame renders a denial for one method as a complete JSON-RPC frame.
func refusalFrame(method string, id json.RawMessage, reason string) ([]byte, error) {
	msg := "blocked by device policy"
	if reason != "" {
		msg += ": " + reason
	}
	if method == methodCallTool {
		// The IsError result is built from the SDK type and marshaled, so the
		// shape is exactly what an MCP client expects for a tool result.
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}
		rb, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("enforce: marshal refusal result: %w", err)
		}
		return marshalFrame(map[string]any{
			"jsonrpc": "2.0", "id": id, "result": json.RawMessage(rb),
		})
	}
	return errorFrame(id, msg), nil
}

// errorFrame builds a JSON-RPC error response for the non-tool methods.
func errorFrame(id json.RawMessage, msg string) []byte {
	b, _ := marshalFrame(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": codeInvalidRequest, "message": msg},
	})
	return b
}

func marshalFrame(v map[string]any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("enforce: marshal frame: %w", err)
	}
	return append(b, '\n'), nil
}

// PolicyDecider adapts the policy engine to the Decider interface. It builds the
// subject for the method from the request params — using the engine's tool
// index for a tools/call, and the read-only data-egress subject for the other
// four, matching the in-process enforcer's subjectFor — evaluates, records the
// decision, and reports whether the call may proceed. In audit mode the engine
// caps severity below deny, so Allowed() is true and the call forwards while the
// intended verdict is still recorded: the harness observes without refusing,
// exactly as a standalone server does under an audit policy.
type PolicyDecider struct {
	engine *policy.Engine
	audit  *audit.AuditLog
	logger *slog.Logger
}

// NewPolicyDecider builds the engine-backed decider.
func NewPolicyDecider(engine *policy.Engine, a *audit.AuditLog, logger *slog.Logger) *PolicyDecider {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &PolicyDecider{engine: engine, audit: a, logger: logger}
}

// Decide evaluates the request and records the verdict.
func (d *PolicyDecider) Decide(ctx context.Context, method string, params json.RawMessage) (bool, string) {
	subj := d.subjectFor(method, params)
	v := d.engine.Evaluate(ctx, subj)
	if d.audit != nil {
		_, _ = d.audit.Append("policy.decided", map[string]any{
			"subject":  v.Subject,
			"verdict":  v.Severity.String(),
			"intended": v.Intended.String(),
			"mode":     string(v.Mode),
			"rules":    v.Rules,
		})
	}
	if !v.Allowed() {
		return false, v.Reason()
	}
	return true, ""
}

// subjectFor mirrors the in-process enforcer's subjectFor over raw params.
func (d *PolicyDecider) subjectFor(method string, params json.RawMessage) policy.Subject {
	switch method {
	case methodCallTool:
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(params, &p)
		return d.engine.SubjectForTool(method, p.Name)
	case methodReadResource:
		var p struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(params, &p)
		return dataEgressSubject(method, p.URI)
	case methodGetPrompt:
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(params, &p)
		return dataEgressSubject(method, p.Name)
	case methodComplete:
		return dataEgressSubject(method, completionName(params))
	default: // methodListen
		return dataEgressSubject(method, methodListen)
	}
}

// dataEgressSubject builds the read-only subject the four non-tool data-egress
// methods share, so a rule written as annotation:read-only or toolset:"*"
// covers them — a resource exposing the same state as a tool is not a way
// around the rule covering that tool.
func dataEgressSubject(method, name string) policy.Subject {
	return policy.Subject{
		Scope:  policy.ScopeCall,
		Method: method,
		Facts:  policy.ToolFacts{Name: name, ReadOnly: true},
	}
}

// completionName labels a completion by what it completes against, never the
// prefix typed.
func completionName(params json.RawMessage) string {
	var p struct {
		Ref *struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		} `json:"ref"`
		Argument struct {
			Name string `json:"name"`
		} `json:"argument"`
	}
	_ = json.Unmarshal(params, &p)
	switch {
	case p.Ref != nil && p.Ref.Name != "":
		return p.Ref.Name + "." + p.Argument.Name
	case p.Ref != nil && p.Ref.URI != "":
		return p.Ref.URI + "." + p.Argument.Name
	default:
		return p.Argument.Name
	}
}
