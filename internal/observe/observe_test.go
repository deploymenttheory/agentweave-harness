package observe

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/watch"
)

// memDest captures audit entries for assertion.
type memDest struct {
	mu      sync.Mutex
	entries []audit.AuditEntry
}

func (m *memDest) Write(e audit.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}
func (m *memDest) Flush() error { return nil }
func (m *memDest) Close() error { return nil }

func (m *memDest) events() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e.Event)
	}
	return out
}

func (m *memDest) find(event string) (audit.AuditEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.Event == event {
			return e, true
		}
	}
	return audit.AuditEntry{}, false
}

func newObs(t *testing.T) (*Observer, *memDest, *watch.RugPull, *[]string) {
	t.Helper()
	dest := &memDest{}
	log := audit.NewAuditLog(dest)
	var trips []string
	var mu sync.Mutex
	rp := watch.NewRugPull(func(reason string) {
		mu.Lock()
		trips = append(trips, reason)
		mu.Unlock()
	}, log)
	return New(log, rp, nil), dest, rp, &trips
}

// TestAuditRecordsToolCallWithDigestedArgs pins that a tools/call on the wire is
// recorded as tool.call with a digest of its arguments, never the raw values —
// the chain must be reviewable without becoming a store of everything typed.
func TestAuditRecordsToolCallWithDigestedArgs(t *testing.T) {
	obs, dest, _, _ := newObs(t)

	obs.OnClientFrame(
		[]byte(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Type","arguments":{"text":"hunter2 secret"}}}`,
		),
	)

	e, ok := dest.find("tool.call")
	if !ok {
		t.Fatalf("no tool.call recorded; events=%v", dest.events())
	}
	raw := string(e.Payload)
	if strings.Contains(raw, "hunter2") || strings.Contains(raw, "secret") {
		t.Fatalf("raw argument value leaked into the audit entry: %s", raw)
	}
	if !strings.Contains(raw, "args_sha256") || !strings.Contains(raw, `"tool":"Type"`) {
		t.Fatalf("tool.call payload missing tool/digest: %s", raw)
	}
}

// TestAuditCoversTheDecidableMethods pins that each decidable method reaching
// the wire lands a record — the harness chain is authoritative for MCP events.
func TestAuditCoversTheDecidableMethods(t *testing.T) {
	obs, dest, _, _ := newObs(t)
	frames := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"X"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file://x"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"P","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"completion/complete","params":{"argument":{"name":"a","value":"v"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"subscriptions/listen","params":{}}`,
		`{"jsonrpc":"2.0","id":6,"method":"server/discover","params":{}}`,
	}
	for _, f := range frames {
		obs.OnClientFrame([]byte(f))
	}
	want := []string{
		"tool.call",
		"resource.read",
		"prompt.get",
		"completion.complete",
		"subscriptions.listen",
		"server.discover",
	}
	for _, w := range want {
		if _, ok := dest.find(w); !ok {
			t.Errorf("missing audit event %q; got %v", w, dest.events())
		}
	}
}

// TestNonDecidableMethodsAreNotAudited pins that ordinary protocol chatter
// (initialize, notifications, tools/list) is not recorded as a decidable-method
// event — the chain records decisions, not the whole transcript.
func TestNonDecidableMethodsAreNotAudited(t *testing.T) {
	obs, dest, _, _ := newObs(t)
	obs.OnClientFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	obs.OnClientFrame([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	for _, e := range dest.events() {
		switch e {
		case "tool.call", "resource.read", "prompt.get", "completion.complete":
			t.Fatalf("non-decidable method produced %q", e)
		}
	}
}

// toolsListFrame builds a tools/list response frame with the given tool names.
func toolsListFrame(id string, names ...string) string {
	tools := make([]*mcp.Tool, len(names))
	for i, n := range names {
		tools[i] = &mcp.Tool{Name: n, Description: "d"}
	}
	res := map[string]any{"tools": tools}
	b := mustJSON(map[string]any{"jsonrpc": "2.0", "id": id, "result": res})
	return b
}

// TestManifestFingerprintPinsThenDetectsDrift pins the rug-pull path from the
// wire: the first tools/list pins a baseline, an identical one does not trip,
// and a mutated one does.
func TestManifestFingerprintPinsThenDetectsDrift(t *testing.T) {
	obs, dest, _, trips := newObs(t)

	// Client requests tools/list; server answers. The observer must correlate
	// the id, so feed the request first.
	obs.OnClientFrame([]byte(`{"jsonrpc":"2.0","id":"t1","method":"tools/list"}`))
	obs.OnServerFrame([]byte(toolsListFrame("t1", "Alpha", "Beta")))

	// Same manifest again: no drift.
	obs.OnClientFrame([]byte(`{"jsonrpc":"2.0","id":"t2","method":"tools/list"}`))
	obs.OnServerFrame([]byte(toolsListFrame("t2", "Alpha", "Beta")))
	if len(*trips) != 0 {
		t.Fatalf("identical manifest tripped: %v", *trips)
	}

	// A smuggled tool: drift.
	obs.OnClientFrame([]byte(`{"jsonrpc":"2.0","id":"t3","method":"tools/list"}`))
	obs.OnServerFrame([]byte(toolsListFrame("t3", "Alpha", "Beta", "Exfiltrate")))
	if len(*trips) != 1 {
		t.Fatalf("manifest mutation not detected once; trips=%v", *trips)
	}
	if _, ok := dest.find("rugpull.detected"); !ok {
		t.Errorf("drift not recorded in the chain; events=%v", dest.events())
	}
}

// TestToolIndexBuiltFromTheWire pins that the observed manifest populates the
// tool index the policy engine will read, annotations and all.
func TestToolIndexBuiltFromTheWire(t *testing.T) {
	obs, _, _, _ := newObs(t)
	destructive := true
	tools := []*mcp.Tool{
		{Name: "Read", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		{Name: "Shell", Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive}},
	}
	frame := mustJSON(map[string]any{"jsonrpc": "2.0", "id": "x", "result": map[string]any{"tools": tools}})
	obs.OnClientFrame([]byte(`{"jsonrpc":"2.0","id":"x","method":"tools/list"}`))
	obs.OnServerFrame([]byte(frame))

	ro, ok := obs.Lookup("Read")
	if !ok || !ro.ReadOnly {
		t.Fatalf("Read facts = %+v ok=%v", ro, ok)
	}
	sh, ok := obs.Lookup("Shell")
	if !ok || !sh.Destructive {
		t.Fatalf("Shell facts = %+v ok=%v", sh, ok)
	}
	if _, ok := obs.Lookup("Nonexistent"); ok {
		t.Error("unknown tool resolved")
	}
}

// TestInjectedReListDetectsDriftOutOfBand pins the monitor path: a re-list the
// harness fetched itself (never shown to the client) is fingerprinted through
// the same detector.
func TestInjectedReListDetectsDriftOutOfBand(t *testing.T) {
	obs, _, _, trips := newObs(t)
	obs.OnClientFrame([]byte(`{"jsonrpc":"2.0","id":"t1","method":"tools/list"}`))
	obs.OnServerFrame([]byte(toolsListFrame("t1", "Alpha")))

	// The injected re-list carries a different manifest.
	obs.FingerprintInjected("tools/list", []byte(toolsListFrame("inj", "Alpha", "Evil")))
	if len(*trips) != 1 {
		t.Fatalf("out-of-band drift not detected; trips=%v", *trips)
	}
}

// helpers

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
