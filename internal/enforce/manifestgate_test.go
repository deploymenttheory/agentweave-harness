package enforce

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/manifest"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

func gateSession(t *testing.T, doc string, start time.Time) *manifest.Session {
	t.Helper()
	m, err := manifest.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return manifest.NewSession(m, start)
}

// clock is a settable time source for the gate.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestManifestGateRefusesUndeclaredToolTyped(t *testing.T) {
	start := time.Now()
	c := &clock{t: start}
	inner := &fakeDecider{}
	g := NewManifestGate(gateSession(t,
		`{"version":1,"expires_after":"1h","allow":{"tools":["Snapshot"]}}`, start),
		inner, nil, nil, c.now)

	d := g.Decide(context.Background(), methodCallTool, []byte(`{"name":"Shell"}`))
	if d.Allow || d.Code != wire.RefusalPermissionDenied {
		t.Fatalf("undeclared tool: got %+v, want refusal %s", d, wire.RefusalPermissionDenied)
	}
	if len(inner.seen) != 0 {
		t.Fatal("the inner decider was consulted for a call the manifest refused")
	}
	if d := g.Decide(context.Background(), methodCallTool, []byte(`{"name":"Snapshot"}`)); !d.Allow {
		t.Fatalf("granted tool refused: %+v", d)
	}
}

func TestManifestGateRefusesResourceOutsideGrant(t *testing.T) {
	start := time.Now()
	c := &clock{t: start}
	g := NewManifestGate(gateSession(t,
		`{"version":1,"expires_after":"1h","allow":{"resources":{"files":["C:\\work"]}}}`, start),
		&fakeDecider{}, nil, nil, c.now)

	d := g.Decide(context.Background(), methodReadResource, []byte(`{"uri":"file:///C:/secrets/key.pem"}`))
	if d.Allow || d.Code != wire.RefusalBoundedResourceOutsideManifest {
		t.Fatalf("out-of-grant read: got %+v, want %s", d, wire.RefusalBoundedResourceOutsideManifest)
	}
	if d := g.Decide(context.Background(), methodReadResource,
		[]byte(`{"uri":"file:///C:/work/report.xlsx"}`)); !d.Allow {
		t.Fatalf("in-grant read refused: %+v", d)
	}
}

// TestManifestGateSessionDrainsOnExpiry pins the drain: past expires_after,
// every decidable request — whatever the method or grant — gets the typed
// refusal, and activity cannot bring the session back.
func TestManifestGateSessionDrainsOnExpiry(t *testing.T) {
	start := time.Now()
	c := &clock{t: start}
	g := NewManifestGate(gateSession(t, `{"version":1,"expires_after":"30m"}`, start),
		&fakeDecider{}, nil, nil, c.now)

	if d := g.Decide(context.Background(), methodCallTool, []byte(`{"name":"X"}`)); !d.Allow {
		t.Fatalf("refused before expiry: %+v", d)
	}
	c.t = start.Add(31 * time.Minute)
	for _, method := range []string{methodCallTool, methodReadResource, methodGetPrompt, methodComplete, methodListen} {
		d := g.Decide(context.Background(), method, []byte(`{}`))
		if d.Allow || d.Code != wire.RefusalSessionExpired {
			t.Fatalf("%s after expiry: got %+v, want %s", method, d, wire.RefusalSessionExpired)
		}
	}
}

// TestManifestGateIdleClockOnlyRefreshesOnAllow pins that refused requests do
// not keep a session alive: only a fully-allowed request touches the idle
// clock.
func TestManifestGateIdleClockOnlyRefreshesOnAllow(t *testing.T) {
	start := time.Now()
	c := &clock{t: start}
	inner := &fakeDecider{deny: true, reason: "policy said no"}
	g := NewManifestGate(gateSession(t,
		`{"version":1,"expires_after":"8h","idle_timeout":"5m"}`, start),
		inner, nil, nil, c.now)

	// A refused request at minute 4 must not refresh the clock…
	c.t = start.Add(4 * time.Minute)
	if d := g.Decide(context.Background(), methodCallTool, []byte(`{"name":"X"}`)); d.Allow {
		t.Fatal("inner denial did not propagate")
	}
	// …so at minute 6 the session is idle despite that refused activity.
	c.t = start.Add(6 * time.Minute)
	d := g.Decide(context.Background(), methodCallTool, []byte(`{"name":"X"}`))
	if d.Allow || d.Code != wire.RefusalSessionIdleTimeout {
		t.Fatalf("idle session: got %+v, want %s", d, wire.RefusalSessionIdleTimeout)
	}
}

// TestManifestGateBindsTheAppsGrant pins the argument-level half of the
// resources grant: an App launch outside allow.resources.apps is refused with
// the typed code, a launch with no readable name argument is refused when a
// grant is present (absent is not compliant, or the grant would be
// dodgeable), and other tools are untouched by the apps list.
func TestManifestGateBindsTheAppsGrant(t *testing.T) {
	start := time.Now()
	c := &clock{t: start}
	g := NewManifestGate(gateSession(t,
		`{"version":1,"expires_after":"1h","allow":{"resources":{"apps":["notepad"]}}}`, start),
		&fakeDecider{}, nil, nil, c.now)

	if d := g.Decide(context.Background(), methodCallTool,
		[]byte(`{"name":"App","arguments":{"name":"notepad"}}`)); !d.Allow {
		t.Fatalf("granted app refused: %+v", d)
	}
	d := g.Decide(context.Background(), methodCallTool,
		[]byte(`{"name":"app","arguments":{"name":"cmd"}}`))
	if d.Allow || d.Code != wire.RefusalBoundedResourceOutsideManifest {
		t.Fatalf("ungranted app: got %+v, want %s", d, wire.RefusalBoundedResourceOutsideManifest)
	}
	if d := g.Decide(context.Background(), methodCallTool,
		[]byte(`{"name":"App","arguments":{}}`)); d.Allow {
		t.Fatal("an App launch with no name argument dodged the apps grant")
	}
	if d := g.Decide(context.Background(), methodCallTool,
		[]byte(`{"name":"Snapshot","arguments":{}}`)); !d.Allow {
		t.Fatalf("the apps grant leaked onto a non-App tool: %+v", d)
	}
}

// TestManifestGateNilSessionIsInner pins the unconditional-composition
// contract: no manifest, no gate.
func TestManifestGateNilSessionIsInner(t *testing.T) {
	inner := &fakeDecider{}
	if got := NewManifestGate(nil, inner, nil, nil, nil); got != Decider(inner) {
		t.Fatal("nil session did not return the inner decider unchanged")
	}
}

// TestManifestGateOversizedNameIsClippedBeforeMatching pins the pre-policy
// sanitization on the gate path: a huge caller-supplied name neither matches a
// grant nor reaches the audit chain unbounded.
func TestManifestGateOversizedNameIsClippedBeforeMatching(t *testing.T) {
	start := time.Now()
	c := &clock{t: start}
	g := NewManifestGate(gateSession(t,
		`{"version":1,"expires_after":"1h","allow":{"tools":["Snapshot"]}}`, start),
		&fakeDecider{}, nil, nil, c.now)

	huge := make([]byte, 64*1024)
	for i := range huge {
		huge[i] = 'a'
	}
	params, _ := json.Marshal(map[string]string{"name": string(huge)})
	d := g.Decide(context.Background(), methodCallTool, params)
	if d.Allow {
		t.Fatal("oversized undeclared name allowed")
	}
	if d.Code != wire.RefusalPermissionDenied {
		t.Fatalf("oversized name: got %+v", d)
	}
}
