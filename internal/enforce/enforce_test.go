package enforce

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy/policytest"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
)

// fakeDecider denies when deny is true, with the given reason.
type fakeDecider struct {
	deny    bool
	reason  string
	seen    []string // methods it was asked about
	lastRaw json.RawMessage
}

func (d *fakeDecider) Decide(_ context.Context, method string, params json.RawMessage) (bool, string) {
	d.seen = append(d.seen, method)
	d.lastRaw = params
	return !d.deny, d.reason
}

func mustFrame(t *testing.T, b []byte) map[string]any {
	t.Helper()
	if b == nil {
		t.Fatal("expected a refusal frame, got nil (forwarded)")
	}
	if b[len(b)-1] != '\n' {
		t.Fatal("refusal frame is not newline-terminated")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("refusal frame is not JSON: %v\n%s", err, b)
	}
	return m
}

// TestNonDecidableAndNonRequestFramesForward pins that the interceptor only
// touches the five decidable request methods: notifications, responses,
// initialize and tools/list all forward (nil), and the decider is never asked.
func TestNonDecidableAndNonRequestFramesForward(t *testing.T) {
	d := &fakeDecider{deny: true}
	i := NewInterceptor(d, nil)
	for _, frame := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":3,"result":{"ok":true}}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"X"}}`, // no id: a notification, not decidable
	} {
		if out := i.Intercept([]byte(frame)); out != nil {
			t.Fatalf("frame was intercepted but should forward: %s", frame)
		}
	}
	if len(d.seen) != 0 {
		t.Fatalf("decider consulted for non-decidable frames: %v", d.seen)
	}
}

// TestAllowedRequestForwards pins that an allowed decidable request forwards
// (returns nil) after being decided.
func TestAllowedRequestForwards(t *testing.T) {
	d := &fakeDecider{deny: false}
	i := NewInterceptor(d, nil)
	if out := i.Intercept(
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Snapshot"}}`),
	); out != nil {
		t.Fatalf("allowed call was refused: %s", out)
	}
	if len(d.seen) != 1 || d.seen[0] != "tools/call" {
		t.Fatalf("decider not consulted correctly: %v", d.seen)
	}
}

// TestToolCallRefusalIsAnIsErrorResult pins the tools/call shape: a JSON-RPC
// success frame carrying a result with isError true and the reason as text, so
// the model can read it and adapt. Never a JSON-RPC error.
func TestToolCallRefusalIsAnIsErrorResult(t *testing.T) {
	d := &fakeDecider{deny: true, reason: "tpm failed"}
	i := NewInterceptor(d, nil)
	m := mustFrame(t, i.Intercept([]byte(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"Shell"}}`)))

	if _, isErr := m["error"]; isErr {
		t.Fatalf("tools/call refusal is a JSON-RPC error, want an IsError result: %v", m)
	}
	result, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result object: %v", m)
	}
	if result["isError"] != true {
		t.Fatalf("result.isError not true: %v", result)
	}
	if id, _ := m["id"].(float64); id != 42 {
		t.Fatalf("refusal id = %v, want 42", m["id"])
	}
	text := resultText(t, result)
	if !strings.Contains(text, "tpm failed") {
		t.Fatalf("reason not surfaced to the model: %q", text)
	}
}

// TestDataEgressRefusalsAreJSONRPCErrors pins that the four non-tool decidable
// methods refuse with a JSON-RPC error (they have no IsError envelope), echoing
// the request id and the InvalidRequest code.
func TestDataEgressRefusalsAreJSONRPCErrors(t *testing.T) {
	cases := map[string]string{
		"resources/read":       `{"jsonrpc":"2.0","id":"a","method":"resources/read","params":{"uri":"file://x"}}`,
		"prompts/get":          `{"jsonrpc":"2.0","id":"b","method":"prompts/get","params":{"name":"P"}}`,
		"completion/complete":  `{"jsonrpc":"2.0","id":"c","method":"completion/complete","params":{"argument":{"name":"a"}}}`,
		"subscriptions/listen": `{"jsonrpc":"2.0","id":"d","method":"subscriptions/listen","params":{}}`,
	}
	for method, frame := range cases {
		d := &fakeDecider{deny: true, reason: "nope"}
		i := NewInterceptor(d, nil)
		m := mustFrame(t, i.Intercept([]byte(frame)))
		if _, hasResult := m["result"]; hasResult {
			t.Errorf("%s refusal carries a result, want a JSON-RPC error: %v", method, m)
		}
		e, ok := m["error"].(map[string]any)
		if !ok {
			t.Errorf("%s refusal has no error object: %v", method, m)
			continue
		}
		if code, _ := e["code"].(float64); int(code) != codeInvalidRequest {
			t.Errorf("%s refusal code = %v, want %d", method, e["code"], codeInvalidRequest)
		}
		if msg, _ := e["message"].(string); !strings.Contains(msg, "nope") {
			t.Errorf("%s refusal message missing reason: %q", method, msg)
		}
	}
}

// TestPolicyDeciderRefusesOnFailingSignal pins the engine-backed decider end to
// end: an enforcing policy whose rule requires a signal that fails yields a
// deny, and the same policy allows when the signal passes.
func TestPolicyDeciderRefusesOnFailingSignal(t *testing.T) {
	pol := denyShellWhenSignalFails(t)
	index := policytest.StaticIndex{
		"Shell": {Name: "Shell", Toolset: "system", Destructive: true},
	}

	// Signal failing → deny.
	failEng := policytest.NewEngine(pol, index, map[string]signals.Status{"tpm-present": signals.Fail})
	dec := NewPolicyDecider(failEng, nil, nil)
	allow, reason := dec.Decide(context.Background(), "tools/call", []byte(`{"name":"Shell"}`))
	if allow {
		t.Fatal("failing signal did not deny the destructive tool")
	}
	if reason == "" {
		t.Error("deny carried no reason")
	}

	// Signal passing → allow.
	passEng := policytest.NewEngine(pol, index, map[string]signals.Status{"tpm-present": signals.Pass})
	if allow, _ := NewPolicyDecider(passEng, nil, nil).Decide(
		context.Background(), "tools/call", []byte(`{"name":"Shell"}`)); !allow {
		t.Fatal("passing signal did not allow the tool")
	}
}

// TestPolicyDeciderAuditModeForwards pins that in audit mode the decider
// forwards (the engine caps severity below deny) even when the signal fails —
// the harness observes without refusing, as a standalone server does.
func TestPolicyDeciderAuditModeForwards(t *testing.T) {
	pol := denyShellWhenSignalFails(t)
	pol.Mode = policy.ModeAuditOnly
	index := policytest.StaticIndex{"Shell": {Name: "Shell", Destructive: true}}
	eng := policytest.NewEngine(pol, index, map[string]signals.Status{"tpm-present": signals.Fail})
	if allow, _ := NewPolicyDecider(eng, nil, nil).Decide(
		context.Background(), "tools/call", []byte(`{"name":"Shell"}`)); !allow {
		t.Fatal("audit mode refused; it must observe, not refuse")
	}
}

// resultText pulls the first text content out of a tool result.
func resultText(t *testing.T, result map[string]any) string {
	t.Helper()
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("result has no content: %v", result)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text
}

// denyShellWhenSignalFails builds an enforcing policy: the Shell tool requires
// tpm-present, on_fail deny.
func denyShellWhenSignalFails(t *testing.T) *policy.Policy {
	t.Helper()
	doc := `{
	  "version": 1,
	  "mode": "enforce",
	  "signals": {"tpm-present": {"ttl": "0s"}},
	  "rules": [
	    {"name": "shell-needs-tpm", "match": {"tool": "Shell"}, "require": ["tpm-present"], "on_fail": "deny"}
	  ]
	}`
	pol, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return pol
}
