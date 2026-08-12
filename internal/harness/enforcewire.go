package harness

// enforcewire builds the policy engine that decides the proxied traffic and
// installs it as the proxy's refusal seam. The engine reads its tool facts from
// the observer's wire-built index and its signals from the servant over the
// control channel, so the whole decision is reached in the harness process,
// on the wire, without consulting the server it governs.

import (
	"log/slog"
	"os"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/internal/control"
	"github.com/deploymenttheory/agentweave-harness/internal/enforce"
	"github.com/deploymenttheory/agentweave-harness/internal/observe"
	"github.com/deploymenttheory/agentweave-harness/internal/proxy"
)

// loadHarnessPolicy parses the policy document if one is configured. It parses
// but does not yet validate signal ids: the set of valid ids is what the
// servant advertises, which is not known until it connects, so validation waits
// for installEnforcement.
func loadHarnessPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		// No policy configured is a first-class outcome, not an error: the
		// harness then only observes. The caller distinguishes it by the nil
		// policy, so a sentinel error would be the wrong shape here.
		return nil, nil //nolint:nilnil // "observe only" is a valid nil policy
	}
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

// installEnforcement builds the engine and swaps the fail-closed interceptor for
// the real policy decider, reporting whether the decider was actually installed.
// It runs on the servant goroutine once the channel is up, before the hello.ack:
// the ack's mode is derived from the return value, so the server is told
// "enforce" only when a live decider stands in front of it — never from the
// policy document alone. Serve must be started after it returns, so the engine's
// signal round-trips can be answered (installation itself does no channel IO;
// the registry closures are registered, not called).
//
// If the policy names a signal this servant cannot evaluate, the session stays
// as it was: fail-closed under an enforcing policy (the DenyAll installed before
// the pump started), observe-only otherwise. Serving a weaker posture than the
// document describes is the failure being avoided.
func installEnforcement(
	p *proxy.Proxy,
	sess *control.Session,
	policyDoc *policy.Policy,
	obs *observe.Observer,
	auditLog *audit.AuditLog,
	logger *slog.Logger,
) bool {
	if policyDoc == nil {
		return false // no policy: pure observe, no interceptor
	}
	known := knownSignalIDs(sess.Hello.Capabilities)
	if err := policyDoc.Validate(known); err != nil {
		logger.Error("harness: policy invalid against this server's signals; enforcement not activated",
			"err", wrapValidate(err, sess.Hello.Capabilities))
		return false
	}
	reg := buildChannelRegistry(sess, policyDoc.SignalIDs())
	engine := policy.NewEngine(policyDoc, reg, obs, func() *signals.Env { return &signals.Env{} })
	decider := enforce.NewPolicyDecider(engine, auditLog, logger)
	p.SetInterceptor(enforce.NewInterceptor(decider, logger))
	logger.Info("harness: enforcement active",
		"mode", string(policyDoc.Mode),
		"signals", policyDoc.SignalIDs(),
		"rules", len(policyDoc.Rules))
	return true
}
