package harness

// enforcewire builds the policy engines that decide the proxied traffic and
// installs them as the proxy's refusal seam. The layers — managed policy
// (env-pointed), user policy (--policy-config), session manifest
// (--session-manifest) — compose narrow-only per docs/policy-config.md; each
// rule-bearing layer gets its own engine (rules are never merged into one
// attribution space) reading its signals from the servant over the control
// channel, and the strictest verdict wins. The whole decision is reached in
// the harness process, on the wire, without consulting the server it governs.

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/manifest"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/internal/control"
	"github.com/deploymenttheory/agentweave-harness/internal/enforce"
	"github.com/deploymenttheory/agentweave-harness/internal/observe"
	"github.com/deploymenttheory/agentweave-harness/internal/proxy"
)

// EnvManagedPolicy points at the fleet operator's managed policy document.
// An unset variable means there is no managed layer; a set variable naming a
// file that cannot be loaded refuses to start — silently running wider than
// the fleet operator intended is the failure being prevented.
const EnvManagedPolicy = "AGENTWEAVE_MANAGED_POLICY"

// sessionLayers is everything the layer loading produced for one session: the
// composed scalar posture plus per-layer rule documents, and the manifest's
// session clocks. Either half may be nil — a manifest-only session is bounded
// but has no policy rules, a policy-only session is the pre-manifest world.
type sessionLayers struct {
	composed *manifest.Composed
	session  *manifest.Session
}

// enforcing reports whether the composed posture asks for wire enforcement.
func (l *sessionLayers) enforcing() bool {
	return l.composed != nil && l.composed.Config.Mode == policy.ModeEnforcing
}

// bounded reports whether a session manifest is present.
func (l *sessionLayers) bounded() bool { return l.session != nil }

// loadLayers loads and composes the policy layers. Every named layer that
// cannot be loaded is a hard error, never a fallback to "no layer" —
// including the env-pointed managed policy, whose absence from disk must not
// degrade to unmanaged. Documents are parsed but not yet validated against
// signal ids: the set of legal ids is what the servant advertises, which is
// not known until it connects (installEnforcement validates then).
func loadLayers(cfg Config) (*sessionLayers, error) {
	var managed, user *policy.Policy
	if path := os.Getenv(EnvManagedPolicy); path != "" {
		p, err := readPolicyFile(path)
		if err != nil {
			return nil, fmt.Errorf("harness: managed policy (%s): %w", EnvManagedPolicy, err)
		}
		managed = p
	}
	if cfg.PolicyConfig != "" {
		p, err := readPolicyFile(cfg.PolicyConfig)
		if err != nil {
			return nil, err
		}
		user = p
	}
	composed, err := manifest.Compose(managed, user)
	if err != nil {
		return nil, fmt.Errorf("harness: compose policy layers: %w", err)
	}
	var mf *manifest.Manifest
	if cfg.SessionManifest != "" {
		mf, err = manifest.Load(cfg.SessionManifest)
		if err != nil {
			return nil, fmt.Errorf("harness: session manifest: %w", err)
		}
	}
	composed, err = manifest.ApplyManifest(composed, mf)
	if err != nil {
		return nil, fmt.Errorf("harness: apply session manifest: %w", err)
	}
	return &sessionLayers{composed: composed, session: manifest.NewSession(mf, time.Now())}, nil
}

// readPolicyFile reads and parses one policy layer.
func readPolicyFile(path string) (*policy.Policy, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied policy path, by design
	if err != nil {
		return nil, wrapReadPolicy(err)
	}
	pol, err := policy.Parse(b)
	if err != nil {
		return nil, wrapParsePolicy(err)
	}
	return pol, nil
}

// installEnforcement builds one engine per rule layer and swaps the
// fail-closed interceptor for the real deciders, reporting whether the
// session is now policy-enforcing on the wire — the fact the hello.ack's mode
// must carry. It runs on the servant goroutine once the channel is up, before
// the ack, and does no channel IO itself.
//
// Every rule layer must validate against the signals this servant advertised;
// any failure leaves the session as it was — fail-closed under an enforcing
// composition (the DenyAll installed before the pump), observe-only otherwise.
// Serving a weaker posture than the layers describe is the failure being
// avoided. The manifest gate wraps whatever decider is installed, so a
// bounded session stays bounded on both paths.
func installEnforcement(
	p *proxy.Proxy,
	sess *control.Session,
	layers *sessionLayers,
	obs *observe.Observer,
	auditLog *audit.AuditLog,
	logger *slog.Logger,
) bool {
	if layers.composed == nil {
		return false // no policy layers: any manifest gate installed pre-pump stands
	}
	known := knownSignalIDs(sess.Hello.Capabilities)
	for _, layer := range layers.composed.RuleLayers {
		if err := layer.Validate(known); err != nil {
			logger.Error("harness: policy layer invalid against this server's signals; enforcement not activated",
				"err", wrapValidate(err, sess.Hello.Capabilities))
			return false
		}
	}
	engines := make([]*policy.Engine, 0, len(layers.composed.RuleLayers))
	for _, layer := range layers.composed.RuleLayers {
		reg := buildChannelRegistry(sess, layer.SignalIDs())
		engines = append(engines, policy.NewEngine(layer, reg, obs, func() *signals.Env { return &signals.Env{} }))
	}
	decider := enforce.NewPolicyDecider(engines, auditLog, logger)
	gated := enforce.NewManifestGate(layers.session, decider, auditLog, logger, nil)
	p.SetInterceptor(enforce.NewInterceptor(gated, logger))
	logger.Info("harness: enforcement active",
		"mode", string(layers.composed.Config.Mode),
		"rule_layers", len(layers.composed.RuleLayers),
		"bounded", layers.bounded())
	return layers.enforcing()
}
