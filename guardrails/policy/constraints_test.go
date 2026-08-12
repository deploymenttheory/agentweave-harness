package policy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy/policytest"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
)

// constraintPolicy parses an enforcing policy whose one rule constrains the
// Type tool's arguments as given (a JSON object for the constraints block).
func constraintPolicy(t *testing.T, constraints string) *policy.Policy {
	t.Helper()
	doc := `{
	  "version": 1,
	  "mode": "enforce",
	  "signals": {},
	  "rules": [
	    {"name": "bounded-typing", "match": {"tool": "Type"}, "require": [],
	     "constraints": ` + constraints + `, "on_fail": "deny"}
	  ]
	}`
	pol, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return pol
}

func constraintEngine(t *testing.T, constraints string) *policy.Engine {
	t.Helper()
	pol := constraintPolicy(t, constraints)
	if err := pol.Validate(nil); err != nil {
		t.Fatalf("validate: %v", err)
	}
	index := policytest.StaticIndex{"Type": {Name: "Type", Toolset: "input"}}
	return policytest.NewEngine(pol, index, map[string]signals.Status{})
}

func typeSubject(args map[string]any) policy.Subject {
	return policy.Subject{
		Scope: policy.ScopeCall, Method: "tools/call",
		Facts:     policy.ToolFacts{Name: "Type", Toolset: "input"},
		Arguments: args,
	}
}

// TestArgumentPatternsAreRE2Bounded pins why the pattern language bounds
// evaluation: it is RE2, which cannot backtrack — evaluation is linear in the
// input — and the proof is that a backreference, the construct that makes
// backtracking engines exponential, does not compile and is refused at
// validation.
func TestArgumentPatternsAreRE2Bounded(t *testing.T) {
	pol := constraintPolicy(t, `{"text": {"pattern": "^(a+)\\1$"}}`)
	err := pol.Validate(nil)
	// Validate collects problems as rendered text under ErrInvalidPolicy (the
	// sentinel appears in the message, like every rule-level problem), so the
	// assertions here are textual, matching the package's own tests.
	if err == nil || !strings.Contains(err.Error(), policy.ErrInvalidConstraint.Error()) {
		t.Fatalf("a backreference pattern validated: %v", err)
	}
	if !strings.Contains(err.Error(), "linear") {
		t.Fatalf("the refusal does not explain the linearity guarantee: %v", err)
	}
}

// requireConstraintError asserts a validation failure that names the
// constraint sentinel in its rendered problems.
func requireConstraintError(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), policy.ErrInvalidConstraint.Error()) {
		t.Fatalf("%s validated: %v", what, err)
	}
}

func TestConstraintValidationRefusesDeadConfig(t *testing.T) {
	// A constraint that constrains nothing.
	requireConstraintError(t, constraintPolicy(t, `{"text": {}}`).Validate(nil), "an empty constraint")
	// min > max can never pass.
	requireConstraintError(t, constraintPolicy(t, `{"n": {"min": 5, "max": 1}}`).Validate(nil), "min > max")
	// Constraints on a startup rule can never evaluate.
	doc := `{
	  "version": 1, "mode": "enforce", "signals": {"s": {}},
	  "rules": [{"name": "st", "match": {"scope": "startup", "toolset": "*"}, "require": ["s"],
	    "constraints": {"x": {"min": 1}}, "on_fail": "deny"}]
	}`
	pol, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	requireConstraintError(t, pol.Validate([]string{"s"}), "startup-rule constraints")
	// A rule with constraints and no required signals is NOT dead config.
	if err := constraintPolicy(t, `{"text": {"max_length": 10}}`).Validate(nil); err != nil {
		t.Fatalf("a constraints-only rule failed validation: %v", err)
	}
}

func TestConstraintEvaluation(t *testing.T) {
	eng := constraintEngine(t,
		`{"text": {"max_length": 8, "pattern": "^[a-z ]+$"}, "count": {"min": 1, "max": 3}}`)

	cases := []struct {
		name  string
		args  map[string]any
		allow bool
	}{
		{"compliant", map[string]any{"text": "hello", "count": 2.0}, true},
		{"too long", map[string]any{"text": "belligerent", "count": 2.0}, false},
		{"pattern miss", map[string]any{"text": "HELLO", "count": 2.0}, false},
		{"below min", map[string]any{"text": "hello", "count": 0.0}, false},
		{"above max", map[string]any{"text": "hello", "count": 9.0}, false},
		{"absent argument", map[string]any{"text": "hello"}, false},
		{"wrong type", map[string]any{"text": 42, "count": 2.0}, false},
		{"empty argument set", map[string]any{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := eng.Evaluate(context.Background(), typeSubject(tc.args))
			if v.Allowed() != tc.allow {
				t.Fatalf("allowed=%v, want %v (verdict: %s)", v.Allowed(), tc.allow, v.Reason())
			}
		})
	}
}

// TestConstraintSkippedWithoutArgumentContext pins the nil-vs-empty
// distinction: a subject with no argument context (plan-time, startup) skips
// constraints — they are spent where the arguments actually are, at call time.
func TestConstraintSkippedWithoutArgumentContext(t *testing.T) {
	eng := constraintEngine(t, `{"text": {"max_length": 8}}`)
	v := eng.Evaluate(context.Background(), typeSubject(nil))
	if !v.Allowed() {
		t.Fatalf("nil argument context evaluated constraints: %s", v.Reason())
	}
}

// TestConstraintFailureNeverCarriesTheValue pins the never-sent rule for
// argument values: the detail names the argument and the bound, and the
// caller's content appears nowhere in the verdict.
func TestConstraintFailureNeverCarriesTheValue(t *testing.T) {
	eng := constraintEngine(t, `{"text": {"max_length": 4, "pattern": "^[a-z]+$"}}`)
	const secret = "Hunter2SecretValue"
	v := eng.Evaluate(context.Background(), typeSubject(map[string]any{"text": secret}))
	if v.Allowed() {
		t.Fatal("violating value allowed")
	}
	if strings.Contains(v.Reason(), secret) {
		t.Fatalf("the argument value leaked into the verdict: %s", v.Reason())
	}
	for _, f := range v.Failures {
		if strings.Contains(f.Detail, secret) {
			t.Fatalf("the argument value leaked into a failure detail: %s", f.Detail)
		}
	}
}
