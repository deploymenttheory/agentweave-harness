package manifest

import (
	"errors"
	"testing"
	"time"

	"github.com/deploymenttheory/agentweave-harness/wire"
)

func mustParse(t *testing.T, doc string) *Manifest {
	t.Helper()
	m, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func TestParseRequiresExpiry(t *testing.T) {
	_, err := Parse([]byte(`{"version": 1, "allow": {"tools": ["Snapshot"]}}`))
	if !errors.Is(err, ErrNoExpiry) {
		t.Fatalf("a manifest with no expires_after parsed: %v", err)
	}
}

func TestParseRefusesUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`{"version": 1, "expires_after": "30m", "alow": {"tools": []}}`))
	if err == nil {
		t.Fatal("a typo'd grant key parsed silently")
	}
}

func TestParseRefusesWrongVersion(t *testing.T) {
	_, err := Parse([]byte(`{"version": 2, "expires_after": "30m"}`))
	if !errors.Is(err, ErrManifestVersion) {
		t.Fatalf("wrong version parsed: %v", err)
	}
}

func TestParseRefusesMalformedOrigins(t *testing.T) {
	_, err := Parse([]byte(
		`{"version": 1, "expires_after": "30m", "allow": {"resources": {"origins": ["not a host!"]}}}`))
	if err == nil {
		t.Fatal("a malformed origin pattern parsed; it should fail the load, not the first read")
	}
}

// TestAbsentAndEmptyAreDifferentStatements pins the load-bearing distinction:
// an absent list does not restrict its category, an explicitly empty list
// grants nothing in it.
func TestAbsentAndEmptyAreDifferentStatements(t *testing.T) {
	absent := mustParse(t, `{"version": 1, "expires_after": "30m"}`)
	if !absent.AllowsTool("Anything") || !absent.AllowsResource("file:///C:/anything") {
		t.Fatal("an absent allow list restricted its category")
	}

	empty := mustParse(t, `{"version": 1, "expires_after": "30m",
		"allow": {"tools": [], "resources": {"files": [], "origins": []}}}`)
	if empty.AllowsTool("Anything") {
		t.Fatal("an explicitly empty tools list granted a tool")
	}
	if empty.AllowsResource("file:///C:/anything") {
		t.Fatal("explicitly empty resource lists granted a read")
	}
}

func TestAllowsToolIsCaseInsensitive(t *testing.T) {
	m := mustParse(t, `{"version": 1, "expires_after": "30m", "allow": {"tools": ["Snapshot"]}}`)
	if !m.AllowsTool("snapshot") {
		t.Fatal("tool grant is case-sensitive; manifests and manifests' authors disagree on case routinely")
	}
	if m.AllowsTool("Shell") {
		t.Fatal("undeclared tool allowed")
	}
}

func TestAllowsResourceByFilePrefix(t *testing.T) {
	m := mustParse(t, `{"version": 1, "expires_after": "30m",
		"allow": {"resources": {"files": ["C:\\work\\reports"]}}}`)
	for _, uri := range []string{
		`C:\work\reports\q3.xlsx`,
		`file:///C:/work/reports/q3.xlsx`,
		`c:/WORK/reports`,
	} {
		if !m.AllowsResource(uri) {
			t.Errorf("%q refused despite falling under the granted prefix", uri)
		}
	}
	for _, uri := range []string{
		`C:\work\reportsX\q3.xlsx`, // sibling that shares the string prefix
		`C:\othere`,
		`https://example.com/reports`,
	} {
		if m.AllowsResource(uri) {
			t.Errorf("%q allowed despite falling outside the grant", uri)
		}
	}
}

func TestAllowsResourceByOrigin(t *testing.T) {
	m := mustParse(t, `{"version": 1, "expires_after": "30m",
		"allow": {"resources": {"origins": ["intranet.example.com", "*.docs.example.com"]}}}`)
	for _, uri := range []string{
		"https://intranet.example.com/page",
		"https://a.docs.example.com/x?q=1",
	} {
		if !m.AllowsResource(uri) {
			t.Errorf("%q refused despite an allowed origin", uri)
		}
	}
	if m.AllowsResource("https://evil.example.com/") {
		t.Fatal("undeclared origin allowed")
	}
	if m.AllowsResource("intranet.example.com") {
		t.Fatal("a bare name with no scheme was read as a hostname; a path must never wildcard into an origin")
	}
}

// TestExpiredManifestFailsClosed pins the drain semantics at the package
// level: once expires_after elapses, Check refuses with the typed code and
// never recovers — a session's grant is fixed at birth and can only expire.
func TestExpiredManifestFailsClosed(t *testing.T) {
	m := mustParse(t, `{"version": 1, "expires_after": "30m"}`)
	start := time.Now()
	s := NewSession(m, start)

	if code, ok := s.Check(start.Add(29 * time.Minute)); !ok {
		t.Fatalf("session refused before expiry: %s", code)
	}
	code, ok := s.Check(start.Add(30 * time.Minute))
	if ok || code != wire.RefusalSessionExpired {
		t.Fatalf("expiry: got (%q, %v), want (%q, false)", code, ok, wire.RefusalSessionExpired)
	}
	// Touch must not resurrect an expired session.
	s.Touch(start.Add(31 * time.Minute))
	if _, ok := s.Check(start.Add(32 * time.Minute)); ok {
		t.Fatal("an expired session came back after activity")
	}
}

func TestIdleTimeoutRefusesTyped(t *testing.T) {
	m := mustParse(t, `{"version": 1, "expires_after": "8h", "idle_timeout": "5m"}`)
	start := time.Now()
	s := NewSession(m, start)

	if code, ok := s.Check(start.Add(4 * time.Minute)); !ok {
		t.Fatalf("refused while active: %s", code)
	}
	s.Touch(start.Add(4 * time.Minute))
	if code, ok := s.Check(start.Add(8 * time.Minute)); !ok {
		t.Fatalf("idle clock did not refresh on allowed activity: %s", code)
	}
	code, ok := s.Check(start.Add(10 * time.Minute))
	if ok || code != wire.RefusalSessionIdleTimeout {
		t.Fatalf("idle: got (%q, %v), want (%q, false)", code, ok, wire.RefusalSessionIdleTimeout)
	}
}

// TestNilSessionIsNoRestriction pins the absent layer as a first-class state.
func TestNilSessionIsNoRestriction(t *testing.T) {
	var s *Session
	if _, ok := s.Check(time.Now()); !ok {
		t.Fatal("nil session refused")
	}
	if !s.AllowsTool("X") || !s.AllowsResource("file:///y") {
		t.Fatal("nil session restricted")
	}
	s.Touch(time.Now()) // must not panic
}
