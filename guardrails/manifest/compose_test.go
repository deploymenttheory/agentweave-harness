package manifest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"pgregory.net/rapid"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy/policytest"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
)

func basePolicy(mode policy.PolicyMode) *policy.Policy {
	return &policy.Policy{Version: 1, Mode: mode}
}

func TestComposeNilLayers(t *testing.T) {
	composed, err := Compose(nil, nil)
	if err != nil || composed != nil {
		t.Fatalf("both layers absent: got (%v, %v), want (nil, nil)", composed, err)
	}
	user := basePolicy(policy.ModeEnforcing)
	composed, err = Compose(nil, user)
	if err != nil || composed.Config.Mode != policy.ModeEnforcing || len(composed.RuleLayers) != 1 {
		t.Fatalf("user-only composition mangled: %+v, %v", composed, err)
	}
	managed := basePolicy(policy.ModeAuditOnly)
	composed, err = Compose(managed, nil)
	if err != nil || composed.Config.Mode != policy.ModeAuditOnly || len(composed.RuleLayers) != 1 {
		t.Fatalf("managed-only composition mangled: %+v, %v", composed, err)
	}
}

func TestComposeModeIsAuditToEnforceOnly(t *testing.T) {
	// Managed enforce beats user audit: enforcement can be added…
	composed, err := Compose(basePolicy(policy.ModeEnforcing), basePolicy(policy.ModeAuditOnly))
	if err != nil || composed.Config.Mode != policy.ModeEnforcing {
		t.Fatalf("managed enforce + user audit composed to %q", composed.Config.Mode)
	}
	// …and never removed: a managed audit layer must not demote an enforcing user.
	composed, err = Compose(basePolicy(policy.ModeAuditOnly), basePolicy(policy.ModeEnforcing))
	if err != nil || composed.Config.Mode != policy.ModeEnforcing {
		t.Fatalf("managed audit demoted an enforcing user policy to %q", composed.Config.Mode)
	}
	// The composed mode governs every layer's rules.
	for i, layer := range composed.RuleLayers {
		if layer.Mode != policy.ModeEnforcing {
			t.Fatalf("rule layer %d kept mode %q; the stricter mode governs the session", i, layer.Mode)
		}
	}
}

// TestComposeKeepsRuleLayersSeparate pins the shadowing lesson: rules are
// never merged into one attribution space, and the config document that could
// be mistaken for a decidable policy carries no rules at all.
func TestComposeKeepsRuleLayersSeparate(t *testing.T) {
	managed := basePolicy(policy.ModeAuditOnly)
	managed.Signals = map[string]policy.SignalConfig{"tpm": {}}
	managed.Rules = []policy.Rule{{
		Name: "m", Match: policy.Match{Tool: policy.StringSet{"Shell"}},
		Require: []string{"tpm"}, OnFail: policy.SeverityDeny,
	}}
	managed.EnforceHTTPS = true

	user := basePolicy(policy.ModeAuditOnly)
	user.Signals = map[string]policy.SignalConfig{"tpm": {}}
	user.Rules = []policy.Rule{{
		Name: "u", Match: policy.Match{Toolset: policy.StringSet{"*"}},
		Require: []string{"tpm"}, OnFail: policy.SeverityWarn,
	}}

	composed, err := Compose(managed, user)
	if err != nil {
		t.Fatal(err)
	}
	if len(composed.RuleLayers) != 2 {
		t.Fatalf("rule layers: %d, want 2", len(composed.RuleLayers))
	}
	if composed.Config.Rules != nil || composed.Config.RateLimits != nil || composed.Config.Signals != nil {
		t.Fatal(
			"the config document carries rules/limits/signals; handing it to an engine would decide with a merged attribution space",
		)
	}
	if !composed.Config.EnforceHTTPS {
		t.Fatal("enforce_https did not OR")
	}
	// Neither input mutated.
	if user.Mode != policy.ModeAuditOnly || managed.Mode != policy.ModeAuditOnly {
		t.Fatal("Compose mutated an input document's mode")
	}
}

func TestComposeRefusesManagedOperationalBlocks(t *testing.T) {
	managed := basePolicy(policy.ModeAuditOnly)
	managed.Telemetry = policy.TelemetryPolicy{Endpoint: "https://collector.example.com"}
	_, err := Compose(managed, basePolicy(policy.ModeAuditOnly))
	if !errors.Is(err, ErrManagedOperationalBlock) {
		t.Fatalf("managed telemetry block composed: %v", err)
	}
}

func TestComposeEgressIntersects(t *testing.T) {
	managed := basePolicy(policy.ModeAuditOnly)
	managed.Egress = policy.EgressPolicy{
		Enabled:    true,
		Allow:      policy.StringSet{"*.example.com", "static.vendor.io"},
		AllowPorts: []int{443, 80},
	}
	user := basePolicy(policy.ModeAuditOnly)
	user.Egress = policy.EgressPolicy{
		Enabled:    true,
		Allow:      policy.StringSet{"api.example.com", "static.vendor.io", "other.net"},
		AllowPorts: []int{443},
	}

	composed, err := Compose(managed, user)
	if err != nil {
		t.Fatal(err)
	}
	got := composed.Config.Egress.Allow
	slices.Sort(got)
	want := policy.StringSet{"api.example.com", "static.vendor.io"}
	if !slices.Equal(got, want) {
		t.Fatalf("egress allow intersect: got %v, want %v", got, want)
	}
	if !slices.Equal(composed.Config.Egress.AllowPorts, []int{443}) {
		t.Fatalf("ports did not intersect: %v", composed.Config.Egress.AllowPorts)
	}
}

// TestComposeWildcardNeverSurvivesAnExactEntry pins the widening bug the
// structural comparison exists to prevent: one layer allowing only the apex
// must not keep the other layer's whole wildcard subtree alive.
func TestComposeWildcardNeverSurvivesAnExactEntry(t *testing.T) {
	managed := basePolicy(policy.ModeAuditOnly)
	managed.Egress = policy.EgressPolicy{Enabled: true, Allow: policy.StringSet{"*.example.com"}}
	user := basePolicy(policy.ModeAuditOnly)
	user.Egress = policy.EgressPolicy{Enabled: true, Allow: policy.StringSet{"example.com"}}

	composed, err := Compose(managed, user)
	if err != nil {
		t.Fatal(err)
	}
	allow := composed.Config.Egress.Allow
	if slices.Contains(allow, "*.example.com") {
		t.Fatalf("the wildcard survived opposite an exact apex: %v — that widens the user's grant", allow)
	}
	if !slices.Contains(allow, "example.com") {
		t.Fatalf("the exact apex both layers admit was dropped: %v", allow)
	}
}

func TestComposeSingleEnabledEgressWins(t *testing.T) {
	managed := basePolicy(policy.ModeAuditOnly)
	managed.Egress = policy.EgressPolicy{Enabled: true, Allow: policy.StringSet{"api.example.com"}}
	user := basePolicy(policy.ModeAuditOnly)

	composed, err := Compose(managed, user)
	if err != nil {
		t.Fatal(err)
	}
	if !composed.Config.Egress.Enabled || len(composed.Config.Egress.Allow) != 1 {
		t.Fatalf("managed-only egress lost in composition: %+v", composed.Config.Egress)
	}
}

func TestApplyManifestNarrowsEgressToOrigins(t *testing.T) {
	p := basePolicy(policy.ModeEnforcing)
	p.Egress = policy.EgressPolicy{
		Enabled: true,
		Allow:   policy.StringSet{"intranet.example.com", "api.example.com", "other.net"},
	}
	composed, err := Compose(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	m := mustParse(t, `{"version": 1, "expires_after": "30m",
		"allow": {"resources": {"origins": ["intranet.example.com"]}}}`)

	narrowed, err := ApplyManifest(composed, m)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(narrowed.Config.Egress.Allow, policy.StringSet{"intranet.example.com"}) {
		t.Fatalf("manifest origins did not narrow the egress allow-list: %v", narrowed.Config.Egress.Allow)
	}
	// A manifest with no origins leaves egress alone.
	plain := mustParse(t, `{"version": 1, "expires_after": "30m"}`)
	same, err := ApplyManifest(composed, plain)
	if err != nil || len(same.Config.Egress.Allow) != 3 {
		t.Fatalf("an origin-less manifest changed egress: %v, %v", same.Config.Egress.Allow, err)
	}
}

// --- the property pin ------------------------------------------------------

var composePropTools = map[string]policy.ToolFacts{
	"Snapshot":   {Name: "Snapshot", Toolset: "screen", ReadOnly: true},
	"PowerShell": {Name: "PowerShell", Toolset: "shell", Destructive: true},
	"Scrape":     {Name: "Scrape", Toolset: "web", ReadOnly: true, OpenWorld: true},
}

var composePropSignals = []string{"s0", "s1", "s2"}

func drawComposeRule(t *rapid.T, layer string, i int) policy.Rule {
	label := fmt.Sprintf("%s-r%d", layer, i)
	var match policy.Match
	switch rapid.SampledFrom([]string{"tool", "toolset", "wildcard"}).Draw(t, label+"-kind") {
	case "tool":
		match = policy.Match{Tool: policy.StringSet{
			rapid.SampledFrom([]string{"Snapshot", "PowerShell", "Scrape"}).Draw(t, label+"-tool"),
		}}
	case "toolset":
		match = policy.Match{Toolset: policy.StringSet{
			rapid.SampledFrom([]string{"screen", "shell", "web"}).Draw(t, label+"-ts"),
		}}
	default:
		match = policy.Match{Toolset: policy.StringSet{"*"}}
	}
	return policy.Rule{
		Name:    label,
		Match:   match,
		Require: []string{rapid.SampledFrom(composePropSignals).Draw(t, label+"-sig")},
		OnFail: rapid.SampledFrom([]policy.Severity{
			policy.SeverityWarn, policy.SeverityDeny, policy.SeverityKill,
		}).Draw(t, label+"-sev"),
	}
}

func drawComposeLayer(t *rapid.T, label string) *policy.Policy {
	p := basePolicy(policy.ModeAuditOnly)
	if rapid.Bool().Draw(t, label+"-enforcing") {
		p.Mode = policy.ModeEnforcing
	}
	p.Signals = map[string]policy.SignalConfig{}
	for _, s := range composePropSignals {
		p.Signals[s] = policy.SignalConfig{}
	}
	n := rapid.IntRange(0, 4).Draw(t, label+"-rules")
	for i := range n {
		p.Rules = append(p.Rules, drawComposeRule(t, label, i))
	}
	return p
}

// TestLowerLayersOnlyNarrow is the phase's property pin: for any managed and
// user layer and any subject, with every signal failing, the composed
// decision (the strictest verdict across the rule-layer engines) is at least
// as severe as every individual layer evaluated alone. This is the property
// naive rule-union failed — the engine's most-specific/last-wins attribution
// let one layer's weaker rule shadow another's stricter one.
func TestLowerLayersOnlyNarrow(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		managed := drawComposeLayer(rt, "managed")
		user := drawComposeLayer(rt, "user")
		composed, err := Compose(managed, user)
		if err != nil {
			rt.Fatalf("compose: %v", err)
		}

		failing := map[string]signals.Status{}
		for _, s := range composePropSignals {
			failing[s] = signals.Fail
		}
		index := policytest.StaticIndex(composePropTools)

		engines := make([]*policy.Engine, 0, len(composed.RuleLayers))
		for _, layer := range composed.RuleLayers {
			engines = append(engines, policytest.NewEngine(layer, index, failing))
		}

		for tool := range composePropTools {
			subject := policy.Subject{
				Scope: policy.ScopeCall, Method: "tools/call",
				Facts: composePropTools[tool],
			}
			composedSev := MaxVerdict(context.Background(), engines, subject).Severity
			for name, layer := range map[string]*policy.Policy{"managed": managed, "user": user} {
				layerSev := policytest.NewEngine(layer, index, failing).
					Evaluate(context.Background(), subject).Severity
				if composedSev < layerSev {
					rt.Fatalf("composition widened %s for %s: composed %s < %s %s",
						name, tool, composedSev, name, layerSev)
				}
			}
		}
	})
}
