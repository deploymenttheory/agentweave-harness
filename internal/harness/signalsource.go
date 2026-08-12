package harness

// signalsource bridges the policy engine's signal reads to the servant over the
// control channel. The engine evaluates a policy by reading the signals its
// rules require; in the harness those readings do not come from probing this
// host — the harness is not the desktop — but from asking the governed server,
// which is, via signal.evaluate. Each declared signal becomes a Guardrail whose
// Check does that round-trip.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/internal/control"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// buildChannelRegistry registers, for each signal id the policy declares, a
// guardrail that fetches its result from the servant. Registering an id the
// servant did not advertise is deliberate: the round-trip then returns an error
// result, which the engine scores at the requiring rule's severity rather than
// silently passing — a policy naming a signal the device cannot answer must not
// become an allow.
func buildChannelRegistry(sess *control.Session, ids []string) *signals.Registry {
	reg := signals.NewRegistry()
	for _, id := range ids {
		id := id
		reg.Register(signals.Guardrail{
			ID: id,
			Check: func(ctx context.Context, env *signals.Env) signals.Result {
				return fetchSignal(ctx, sess, id, env.Arg)
			},
		})
	}
	return reg
}

// fetchSignal performs one signal.evaluate round-trip and decodes the result.
// Any failure — a dead channel, a malformed reply, an empty result — is an
// error-status result, never a pass: the harness cannot vouch for a signal it
// could not read, and the engine already treats an errored signal as the rule's
// full severity.
func fetchSignal(ctx context.Context, sess *control.Session, id, arg string) signals.Result {
	req := wire.SignalEvaluate{IDs: []string{id}}
	if arg != "" {
		req.Args = map[string]string{id: arg}
	}
	resp, err := sess.Request(ctx, wire.TypeSignalEvaluate, req)
	if err != nil {
		return signals.Result{ID: id, Status: signals.Error, Detail: "control channel: " + err.Error()}
	}
	if resp.Type != wire.TypeSignalResult {
		return signals.Result{ID: id, Status: signals.Error, Detail: "unexpected reply " + resp.Type}
	}
	var sr wire.SignalResult
	if err := wire.Unmarshal(resp, &sr); err != nil {
		return signals.Result{ID: id, Status: signals.Error, Detail: "malformed signal.result: " + err.Error()}
	}
	if len(sr.Results) == 0 {
		return signals.Result{ID: id, Status: signals.Error, Detail: "servant returned no result for " + id}
	}
	var r signals.Result
	if err := json.Unmarshal(sr.Results[0], &r); err != nil {
		return signals.Result{ID: id, Status: signals.Error, Detail: "undecodable result: " + err.Error()}
	}
	if r.ID == "" {
		r.ID = id
	}
	return r
}

// knownSignalIDs is the set of signal ids the servant advertised it can
// evaluate — the set a policy is validated against when it loads, so a policy
// naming a signal this servant does not serve is rejected at startup rather
// than failing per call.
func knownSignalIDs(caps wire.Capabilities) []string {
	return caps.Signals
}

// wrapValidate turns a policy-load failure into a startup error naming the
// servant's advertised capabilities, so the operator sees why a signal was
// rejected.
func wrapValidate(err error, caps wire.Capabilities) error {
	return fmt.Errorf("policy names a signal this server cannot evaluate (advertised: %v): %w",
		caps.Signals, err)
}

func wrapReadPolicy(err error) error  { return fmt.Errorf("harness: read policy: %w", err) }
func wrapParsePolicy(err error) error { return fmt.Errorf("harness: parse policy: %w", err) }
