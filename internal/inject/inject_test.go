package inject

import (
	"encoding/json"
	"strings"
	"testing"
)

func testInjector(stopped *string) *Injector {
	return New(
		func() Status { return Status{Mode: "enforce", Enforcing: true, Bounded: true, RuleLayers: 2} },
		func(reason string) {
			if stopped != nil {
				*stopped = reason
			}
		},
	)
}

// TestToolsAreWellFormedMCPTools pins that the injected definitions are valid
// MCP Tool objects with the expected names — a malformed one would break the
// client's tools/list.
func TestToolsAreWellFormedMCPTools(t *testing.T) {
	names := map[string]bool{}
	for _, raw := range testInjector(nil).Tools() {
		var tool struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"` //nolint:tagliatelle // MCP wire field name
		}
		if err := json.Unmarshal(raw, &tool); err != nil {
			t.Fatalf("injected tool is not valid JSON: %v\n%s", err, raw)
		}
		if tool.Name == "" || tool.Description == "" || len(tool.InputSchema) == 0 {
			t.Fatalf("injected tool is missing a required field: %s", raw)
		}
		names[tool.Name] = true
	}
	for _, want := range []string{ToolGuardrailStatus, ToolKill} {
		if !names[want] {
			t.Fatalf("injected tools missing %q; got %v", want, names)
		}
	}
}

func TestAnswerGuardrailStatus(t *testing.T) {
	text, ok := testInjector(nil).Answer(ToolGuardrailStatus, nil)
	if !ok {
		t.Fatal("GuardrailStatus not answered")
	}
	var s Status
	if err := json.Unmarshal([]byte(text), &s); err != nil {
		t.Fatalf("status is not JSON: %v", err)
	}
	if !s.Enforcing || s.Mode != "enforce" || s.RuleLayers != 2 {
		t.Fatalf("status did not reflect the provider: %+v", s)
	}
}

func TestAnswerKillStopsWithReason(t *testing.T) {
	var stopped string
	inj := testInjector(&stopped)
	text, ok := inj.Answer(ToolKill, json.RawMessage(`{"reason":"done"}`))
	if !ok {
		t.Fatal("Kill not answered")
	}
	if !strings.Contains(stopped, "done") {
		t.Fatalf("stop was not called with the reason: %q", stopped)
	}
	if !strings.Contains(text, "stopping") {
		t.Fatalf("kill result did not confirm the stop: %q", text)
	}
}

func TestAnswerUnknownToolIsNotOurs(t *testing.T) {
	if _, ok := testInjector(nil).Answer("Snapshot", nil); ok {
		t.Fatal("a server tool was claimed by the injector")
	}
}

// TestInterceptorAnswersInjectedCallsAndDelegatesTheRest pins the routing: a
// call to an injected tool is answered here (a success result, id echoed),
// never forwarded; anything else passes to the delegate.
func TestInterceptorAnswersInjectedCallsAndDelegatesTheRest(t *testing.T) {
	var delegated int
	delegate := interceptorFunc(func([]byte) []byte { delegated++; return nil })
	var stopped string
	ic := WrapInterceptor(testInjector(&stopped), delegate)

	// An injected-tool call is answered locally.
	out := ic.Intercept([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"GuardrailStatus"}}`))
	if out == nil {
		t.Fatal("GuardrailStatus call was not answered")
	}
	var resp struct {
		ID     int `json:"id"`
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("answer is not a valid frame: %v\n%s", err, out)
	}
	if resp.ID != 7 || len(resp.Result.Content) == 0 {
		t.Fatalf("answer frame malformed: %s", out)
	}
	if delegated != 0 {
		t.Fatal("an injected-tool call reached the delegate")
	}

	// A server-tool call is delegated.
	if ic.Intercept([]byte(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"Snapshot"}}`)) != nil {
		t.Fatal("a server-tool call was answered locally")
	}
	if delegated != 1 {
		t.Fatalf("server-tool call was not delegated (delegated=%d)", delegated)
	}

	// A notification-shaped tools/call (no id) is delegated, not answered.
	_ = ic.Intercept([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"GuardrailStatus"}}`))
	if delegated != 2 {
		t.Fatal("an id-less injected-tool frame was answered rather than delegated")
	}
}

type interceptorFunc func([]byte) []byte

func (f interceptorFunc) Intercept(raw []byte) []byte { return f(raw) }
