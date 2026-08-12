package enforce

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/manifest"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// ManifestGate enforces the session manifest ahead of the inner decider: the
// two session clocks first (an out-of-time session drains with a typed
// refusal, whatever the request), then the grant lists for the method, then
// the wrapped policy decision. The idle clock is touched only for requests
// the whole chain allowed — a refused call must not keep a session alive.
//
// The gate enforces whenever a manifest is present, regardless of policy
// mode: a manifest has no audit mode, it is a grant, and a grant that only
// logged its bounds would not bound anything.
type ManifestGate struct {
	session *manifest.Session
	inner   Decider
	audit   *audit.AuditLog
	logger  *slog.Logger
	now     func() time.Time
}

// NewManifestGate wraps the inner decider with the session's bounds. A nil
// session gates nothing and returns the inner decider unchanged, so callers
// can compose unconditionally.
func NewManifestGate(
	s *manifest.Session,
	inner Decider,
	a *audit.AuditLog,
	logger *slog.Logger,
	now func() time.Time,
) Decider {
	if s == nil {
		return inner
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return &ManifestGate{session: s, inner: inner, audit: a, logger: logger, now: now}
}

// Decide applies clocks, grant, then the inner decider.
func (g *ManifestGate) Decide(ctx context.Context, method string, params json.RawMessage) Decision {
	t := g.now()
	if code, ok := g.session.Check(t); !ok {
		return g.refused(method, method, code, "the session's grant has run out")
	}
	switch method {
	case methodCallTool:
		name := subjectName(method, params)
		if !g.session.AllowsTool(name) {
			return g.refused(method, name, wire.RefusalPermissionDenied,
				"the session manifest does not grant this tool")
		}
		// The apps grant binds the App tool's name argument — launching an
		// application is a resource acquisition, bounded like a read. An App
		// call with no readable name argument is refused when a grant is
		// present: absent is not compliant, or the grant would be dodgeable.
		if app, isLaunch := launchedApp(name, params); isLaunch && !g.session.AllowsApp(app) {
			return g.refused(method, app, wire.RefusalBoundedResourceOutsideManifest,
				"the application is outside the session manifest's grant")
		}
	case methodReadResource:
		if uri := subjectName(method, params); !g.session.AllowsResource(uri) {
			return g.refused(method, uri, wire.RefusalBoundedResourceOutsideManifest,
				"the resource is outside the session manifest's grant")
		}
	}
	d := g.inner.Decide(ctx, method, params)
	if d.Allow {
		g.session.Touch(t)
	}
	return d
}

// launchedApp reports whether this tools/call is an application launch (the
// App tool, matched case-insensitively) and, if so, which application its
// name argument names — clipped like every caller string. A launch with no
// readable name argument reports "", which no explicit grant contains.
func launchedApp(tool string, params json.RawMessage) (string, bool) {
	if !strings.EqualFold(tool, "App") {
		return "", false
	}
	var p struct {
		Arguments struct {
			Name string `json:"name"`
		} `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	return clipSubject(p.Arguments.Name), true
}

// refused records and builds a typed manifest refusal. The subject in the
// audit record is already clipped by subjectName; the code is the
// machine-readable half, the reason the human one.
func (g *ManifestGate) refused(method, subject, code, reason string) Decision {
	if g.audit != nil {
		_, _ = g.audit.Append("manifest.refused", map[string]any{
			"method": method, "subject": subject, "code": code,
		})
	}
	g.logger.Info("enforce: manifest refused", "method", method, "code", code)
	return Refused(code, reason)
}
