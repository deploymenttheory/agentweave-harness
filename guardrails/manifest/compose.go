package manifest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/deploymenttheory/agentweave-harness/guardrails/hostmatch"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// ErrManagedOperationalBlock reports a managed policy carrying operational
// configuration. The managed layer carries restrictions only: where this
// device's chains, spans and approvals go belongs to the device operator's
// policy, and keeping the managed layer restriction-only is what makes the
// composition auditable — everything it can do is something the agent could
// only experience as "less".
var ErrManagedOperationalBlock = errors.New(
	"managed policy sets an operational block (belongs to the user policy)")

// Composed is the result of folding the policy layers together.
//
// The scalar posture — mode, enforce_https, containment, egress — composes
// into one document, Config. The rule sets deliberately do not: the engine
// attributes each required signal to its single most specific matching rule
// (ties: last wins), so merging two layers' rules into one document would let
// one layer's weaker rule shadow another layer's stricter rule for the same
// signal — a widening, found by this package's own property test. Instead
// each rule-bearing layer keeps its own document (promoted to the composed
// mode) and is evaluated independently; MaxVerdict takes the strictest
// answer, which is narrow-only by construction.
type Composed struct {
	// Config carries the composed scalar posture and the user layer's
	// operational blocks. Its Rules, RateLimits and Signals are empty on
	// purpose: decisions come from RuleLayers, and handing Config to an
	// engine would silently decide with no rules at all.
	Config *policy.Policy
	// RuleLayers are the rule-bearing documents, one per present layer, each
	// with Mode set to the composed mode — the stricter mode governs the
	// session, and promoting a layer's severity is narrowing.
	RuleLayers []*policy.Policy
}

// Compose folds the user policy onto the managed policy, narrow-only per
// docs/policy-config.md: mode audit→enforce only, enforce_https OR, kill
// switches OR, egress allow-lists intersect, rule layers kept separate for
// strictest-wins evaluation. Either layer may be nil; both nil composes to
// nil. Neither input is mutated.
func Compose(managed, user *policy.Policy) (*Composed, error) {
	if managed == nil && user == nil {
		return nil, nil //nolint:nilnil // "no layers" is a valid nil composition
	}
	if managed != nil {
		if err := refuseOperationalBlocks(managed); err != nil {
			return nil, err
		}
	}

	mode := policy.ModeAuditOnly
	for _, p := range []*policy.Policy{managed, user} {
		// Enforcement can be added, never removed.
		if p != nil && p.Mode == policy.ModeEnforcing {
			mode = policy.ModeEnforcing
		}
	}

	// Config: the user document owns the operational blocks; the managed
	// layer's scalar restrictions fold on top.
	var config policy.Policy
	if user != nil {
		config = *user
	} else {
		config = *managed
	}
	config.Mode = mode
	config.Rules = nil
	config.RateLimits = nil
	config.Signals = nil
	config.RequirePlan = nil

	if managed != nil && user != nil {
		// Plaintext can be forbidden, never re-permitted.
		config.EnforceHTTPS = user.EnforceHTTPS || managed.EnforceHTTPS
		// Containment: arming more restricts the agent, never the reverse.
		config.Kill = composeKill(user.Kill, managed.Kill)
		// Egress: the composed reachable set can only shrink.
		egress, err := composeEgress(user.Egress, managed.Egress)
		if err != nil {
			return nil, err
		}
		config.Egress = egress
		// require_plan: union of selectors — more calls can be made to
		// require a plan, never fewer. Consumed as a set, so union in the
		// one config document is sound (no attribution to shadow).
		config.RequirePlan = slices.Concat(user.RequirePlan, managed.RequirePlan)
	} else if managed != nil {
		config.RequirePlan = slices.Clone(managed.RequirePlan)
	} else {
		config.RequirePlan = slices.Clone(user.RequirePlan)
	}

	out := &Composed{Config: &config}
	for _, p := range []*policy.Policy{managed, user} {
		if p == nil {
			continue
		}
		layer := *p
		layer.Mode = mode
		out.RuleLayers = append(out.RuleLayers, &layer)
	}
	return out, nil
}

// MaxVerdict evaluates the subject against every rule layer's engine and
// returns the strictest verdict — severity and intended are the maxima, and
// the contributing rules and failures accumulate so the refusal still names
// what failed. With no engines the subject is allowed: no layers, no rules.
func MaxVerdict(ctx context.Context, engines []*policy.Engine, subject policy.Subject) policy.Verdict {
	if len(engines) == 0 {
		return policy.Verdict{Subject: subject.String(), Severity: policy.SeverityAllow}
	}
	v := engines[0].Evaluate(ctx, subject)
	for _, e := range engines[1:] {
		u := e.Evaluate(ctx, subject)
		if u.Severity > v.Severity {
			v.Severity = u.Severity
		}
		if u.Intended > v.Intended {
			v.Intended = u.Intended
		}
		v.Rules = append(v.Rules, u.Rules...)
		v.Failures = append(v.Failures, u.Failures...)
	}
	return v
}

// ApplyManifest narrows the composed config with the session manifest's
// origins: an enabled egress allow-list intersects with them, so a bounded
// session's network reach shrinks to match what it may read. The manifest
// carries no rules or mode, so nothing else changes. Either input may be nil.
func ApplyManifest(c *Composed, m *Manifest) (*Composed, error) {
	if c == nil || m == nil || m.Allow.Resources.Origins == nil || !c.Config.Egress.Enabled {
		return c, nil
	}
	config := *c.Config
	allow, err := intersectHostSets(policy.StringSet(m.Allow.Resources.Origins), config.Egress.Allow)
	if err != nil {
		return nil, err
	}
	config.Egress.Allow = allow
	return &Composed{Config: &config, RuleLayers: c.RuleLayers}, nil
}

// refuseOperationalBlocks rejects a managed document that configures the
// device-operator concerns. Zero-value comparison is deliberate: the schema
// refuses unknown fields, so "set at all" is detectable this way, and a new
// operational field added to one of these blocks is covered automatically.
func refuseOperationalBlocks(p *policy.Policy) error {
	var offending []string
	if !reflect.DeepEqual(p.Transparency, policy.TransparencyPolicy{}) {
		offending = append(offending, "transparency")
	}
	if !reflect.DeepEqual(p.Telemetry, policy.TelemetryPolicy{}) {
		offending = append(offending, "telemetry")
	}
	if !reflect.DeepEqual(p.Approvals, policy.ApprovalsPolicy{}) {
		offending = append(offending, "approvals")
	}
	if !reflect.DeepEqual(p.Credentials, policy.CredentialsPolicy{}) {
		offending = append(offending, "credentials")
	}
	if !reflect.DeepEqual(p.InFlight, policy.InFlightPolicy{}) {
		offending = append(offending, "inflight")
	}
	if len(offending) > 0 {
		return fmt.Errorf("%w: %s", ErrManagedOperationalBlock, strings.Join(offending, ", "))
	}
	return nil
}

func composeKill(user, managed policy.KillPolicy) policy.KillPolicy {
	out := user
	out.Triggers.PostureDrift = out.Triggers.PostureDrift || managed.Triggers.PostureDrift
	out.Triggers.RugPull = out.Triggers.RugPull || managed.Triggers.RugPull
	out.Triggers.HeartbeatGap = out.Triggers.HeartbeatGap || managed.Triggers.HeartbeatGap
	out.Triggers.Sentinel = out.Triggers.Sentinel || managed.Triggers.Sentinel
	out.Actions.Isolate = out.Actions.Isolate || managed.Actions.Isolate
	out.Actions.Lock = out.Actions.Lock || managed.Actions.Lock
	out.Actions.Shutdown = out.Actions.Shutdown || managed.Actions.Shutdown
	// The shorter delay is the stricter containment.
	if d := managed.Actions.ShutdownDelay; d > 0 && (out.Actions.ShutdownDelay == 0 || d < out.Actions.ShutdownDelay) {
		out.Actions.ShutdownDelay = d
	}
	for _, proc := range managed.Actions.KillProcs {
		if !slices.Contains(out.Actions.KillProcs, proc) {
			out.Actions.KillProcs = append(out.Actions.KillProcs, proc)
		}
	}
	return out
}

// composeEgress narrows the reachable set. One enabled layer wins outright;
// with both enabled the allow-lists and port lists intersect. The operational
// knobs (listen address, system proxy, auth token env) stay the user's — the
// managed layer only shrinks reach.
func composeEgress(user, managed policy.EgressPolicy) (policy.EgressPolicy, error) {
	switch {
	case !managed.Enabled:
		return user, nil
	case !user.Enabled:
		return managed, nil
	}
	out := user
	allow, err := intersectHostSets(managed.Allow, user.Allow)
	if err != nil {
		return policy.EgressPolicy{}, err
	}
	out.Allow = allow
	out.AllowPorts = intersectPorts(user.AllowPorts, managed.AllowPorts)
	// Stricter tier wins; a target must satisfy both layers to be dialable.
	out.BlockAllOutbound = user.BlockAllOutbound || managed.BlockAllOutbound
	out.AllowPrivateNetworks = user.AllowPrivateNetworks && managed.AllowPrivateNetworks
	for _, app := range managed.Applications {
		if !out.Applications.Contains(app) {
			out.Applications = append(out.Applications, app)
		}
	}
	return out, nil
}

// intersectHostSets keeps each entry of either list that the other list
// entirely covers — so "*.example.com" ∩ "api.example.com" keeps the narrower
// "api.example.com", and "*.example.com" survives only opposite another
// wildcard at or above it. Coverage is decided structurally over the
// hostmatch vocabulary (exact names and "*.suffix"), never by probing the
// matcher: an exact entry on one side must not keep the other side's whole
// wildcard alive. The result can only be narrower than both inputs.
func intersectHostSets(a, b policy.StringSet) (policy.StringSet, error) {
	// Compile both lists first so a malformed pattern fails the composition,
	// not the first dial it should have bounded.
	setA, err := hostmatch.Compile(a)
	if err != nil {
		return nil, fmt.Errorf("compose egress allow: %w", err)
	}
	setB, err := hostmatch.Compile(b)
	if err != nil {
		return nil, fmt.Errorf("compose egress allow: %w", err)
	}
	var out policy.StringSet
	for _, entry := range a {
		if coveredBy(entry, b, setB) {
			out = append(out, entry)
		}
	}
	for _, entry := range b {
		if coveredBy(entry, a, setA) && !out.Contains(entry) {
			out = append(out, entry)
		}
	}
	// Never nil: an enabled egress policy with an empty allow-list is refused
	// at validation, and an empty (not absent) intersection must read as
	// "nothing is reachable", so the caller can tell it apart from unset.
	if out == nil {
		out = policy.StringSet{}
	}
	return out, nil
}

// coveredBy reports whether everything the entry admits is admitted by the
// other list. An exact name is covered when the other matcher admits it. A
// wildcard "*.x" (which covers x and every depth below) is covered only by a
// wildcard "*.y" with x at or below y — an exact name on the other side
// covers one host, never a subtree.
func coveredBy(entry string, other policy.StringSet, otherSet *hostmatch.Set) bool {
	if !strings.HasPrefix(entry, "*.") {
		return otherSet.Match(entry)
	}
	x := strings.ToLower(entry[2:])
	for _, o := range other {
		if !strings.HasPrefix(o, "*.") {
			continue
		}
		y := strings.ToLower(o[2:])
		if x == y || strings.HasSuffix(x, "."+y) {
			return true
		}
	}
	return false
}

func intersectPorts(a, b []int) []int {
	if len(a) == 0 {
		return slices.Clone(b)
	}
	if len(b) == 0 {
		return slices.Clone(a)
	}
	var out []int
	for _, p := range a {
		if slices.Contains(b, p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if out == nil {
		out = []int{}
	}
	return out
}
