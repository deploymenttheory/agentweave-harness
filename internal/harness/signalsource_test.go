package harness

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/internal/control"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// servantAnswering stands up a control host, connects a fake servant that
// answers signal.evaluate with the given status, and returns the harness-side
// session with its Serve loop running. It is the deterministic substitute for a
// real governed server in signal-source tests.
func servantAnswering(t *testing.T, status string) *control.Session {
	t.Helper()
	host, err := control.NewHost(slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })

	// AwaitServant must be pending (Accept called) before the servant dials, or
	// the pipe has no instance to connect to — so it runs in a goroutine first.
	type awaited struct {
		sess *control.Session
		err  error
	}
	awaitCh := make(chan awaited, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := host.AwaitServant(ctx)
		awaitCh <- awaited{s, err}
	}()

	conn, err := control.Dial(host.Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Servant side: hello, then answer signal.evaluate.
	w := wire.NewWriter(conn)
	r := wire.NewReader(conn)
	hello, _ := wire.Marshal(1, wire.TypeHello, "", "", wire.Hello{
		ProtoMin: 1, ProtoMax: 1, Token: host.Token,
		Capabilities: wire.Capabilities{Signals: []string{"tpm"}},
	})
	if err := w.Write(hello); err != nil {
		t.Fatal(err)
	}

	got := <-awaitCh
	if got.err != nil {
		t.Fatal(got.err)
	}
	sess := got.sess

	// The servant reader must run before Ack: the pipe is zero-buffer, so Ack
	// blocks writing hello.ack until the servant reads it. This goroutine reads
	// and discards the ack, then answers each signal.evaluate.
	go func() {
		for {
			env, err := r.Read()
			if err != nil {
				return
			}
			if env.Type != wire.TypeSignalEvaluate {
				continue
			}
			var req wire.SignalEvaluate
			_ = wire.Unmarshal(env, &req)
			results := make([]json.RawMessage, 0, len(req.IDs))
			for _, id := range req.IDs {
				results = append(results, json.RawMessage(`{"id":"`+id+`","status":"`+status+`"}`))
			}
			reply, _ := wire.Marshal(1, wire.TypeSignalResult, "", env.ID, wire.SignalResult{Results: results})
			_ = w.Write(reply)
		}
	}()
	go func() { _ = sess.Serve(slog.New(slog.DiscardHandler), map[string]control.Handler{}) }()
	t.Cleanup(func() { _ = sess.Close() })

	if err := sess.Ack(wire.HelloAck{Mode: wire.ModeObserve}); err != nil {
		t.Fatal(err)
	}
	return sess
}

// TestChannelRegistryFetchesSignalsOverTheChannel pins that a guardrail built
// by buildChannelRegistry evaluates by round-tripping to the servant: a servant
// reporting "fail" yields a Fail result.
func TestChannelRegistryFetchesSignalsOverTheChannel(t *testing.T) {
	sess := servantAnswering(t, "fail")
	reg := buildChannelRegistry(sess, []string{"tpm"})

	g, ok := reg.Get("tpm")
	if !ok {
		t.Fatal("tpm not registered")
	}
	res := g.Check(context.Background(), &signals.Env{})
	if res.Status != signals.Fail {
		t.Fatalf("status = %v, want fail", res.Status)
	}
	if res.ID != "tpm" {
		t.Fatalf("result id = %q", res.ID)
	}
}

// TestChannelRegistryPassesThrough pins the allow side: a passing servant yields
// a Pass result, so the same policy would admit the call.
func TestChannelRegistryPassesThrough(t *testing.T) {
	sess := servantAnswering(t, "pass")
	reg := buildChannelRegistry(sess, []string{"tpm"})
	g, _ := reg.Get("tpm")
	if res := g.Check(context.Background(), &signals.Env{}); res.Status != signals.Pass {
		t.Fatalf("status = %v, want pass", res.Status)
	}
}
