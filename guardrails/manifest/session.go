package manifest

import (
	"sync"
	"time"

	"github.com/deploymenttheory/agentweave-harness/wire"
)

// Session is one governed session's view of its manifest: the grant plus the
// two clocks. The harness checks it per decidable frame; when either clock
// runs out the session drains — every decidable request gets a typed refusal
// in the method's shape — rather than being killed.
type Session struct {
	m     *Manifest
	start time.Time

	mu          sync.Mutex
	lastAllowed time.Time
}

// NewSession starts the manifest's clocks. A nil manifest returns a nil
// session, on which every method reports "no restriction" — the absent layer
// is a first-class state, mirroring loadHarnessPolicy's nil policy.
func NewSession(m *Manifest, now time.Time) *Session {
	if m == nil {
		return nil
	}
	return &Session{m: m, start: now, lastAllowed: now}
}

// Check reports whether the session's clocks still admit requests. A
// non-empty code is the typed refusal to surface (session_expired or
// session_idle_timeout).
func (s *Session) Check(now time.Time) (code string, ok bool) {
	if s == nil {
		return "", true
	}
	if now.Sub(s.start) >= s.m.ExpiresAfter.Std() {
		return wire.RefusalSessionExpired, false
	}
	if idle := s.m.IdleTimeout.Std(); idle > 0 {
		s.mu.Lock()
		last := s.lastAllowed
		s.mu.Unlock()
		if now.Sub(last) >= idle {
			return wire.RefusalSessionIdleTimeout, false
		}
	}
	return "", true
}

// Touch refreshes the idle clock. Called only for requests that were allowed:
// a refused request must not keep a session alive.
func (s *Session) Touch(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.lastAllowed = now
	s.mu.Unlock()
}

// AllowsTool is the session view of Manifest.AllowsTool; nil allows.
func (s *Session) AllowsTool(name string) bool {
	return s == nil || s.m.AllowsTool(name)
}

// AllowsResource is the session view of Manifest.AllowsResource; nil allows.
func (s *Session) AllowsResource(uri string) bool {
	return s == nil || s.m.AllowsResource(uri)
}

// AllowsApp is the session view of Manifest.AllowsApp; nil allows.
func (s *Session) AllowsApp(name string) bool {
	return s == nil || s.m.AllowsApp(name)
}
