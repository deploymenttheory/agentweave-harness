package harness

import (
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/manifest"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

func layersWithEgress(e policy.EgressPolicy) *sessionLayers {
	return &sessionLayers{composed: &manifest.Composed{
		Config: &policy.Policy{Version: 1, Egress: e},
	}}
}

// TestEgressNeedsActuationOnlyForOSTiers pins that the harness pushes OS
// firewall enforcement to the server only when the composed policy asks for
// it: the proxy-only tier forces nothing through the proxy, so there is
// nothing for the host to firewall and no actuation to push.
func TestEgressNeedsActuationOnlyForOSTiers(t *testing.T) {
	cases := []struct {
		name string
		e    policy.EgressPolicy
		want bool
	}{
		{"disabled", policy.EgressPolicy{Enabled: false}, false},
		{"proxy-only", policy.EgressPolicy{Enabled: true, Allow: policy.StringSet{"a.example.com"}}, false},
		{"scoped", policy.EgressPolicy{Enabled: true, Applications: policy.StringSet{`C:\a.exe`}}, true},
		{"global", policy.EgressPolicy{Enabled: true, BlockAllOutbound: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := egressNeedsActuation(layersWithEgress(tc.e)); got != tc.want {
				t.Fatalf("egressNeedsActuation(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
	// No composed policy at all: nothing to actuate.
	if egressNeedsActuation(&sessionLayers{}) {
		t.Fatal("a layerless session asked for egress actuation")
	}
}
