package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/deploymenttheory/agentweave-harness/wire"
)

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newHost(t *testing.T) *Host {
	t.Helper()
	h, err := NewHost(slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func sendHello(t *testing.T, conn net.Conn, hello wire.Hello) {
	t.Helper()
	env, err := wire.Marshal(1, wire.TypeHello, "", "", hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.NewWriter(conn).Write(env); err != nil {
		t.Fatal(err)
	}
}

func awaitAsync(h *Host) (chan *Session, chan error) {
	sessions, errs := make(chan *Session, 1), make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := h.AwaitServant(ctx)
		if err != nil {
			errs <- err
			return
		}
		sessions <- s
	}()
	return sessions, errs
}

func TestHandshakeNegotiatesAndAcks(t *testing.T) {
	h := newHost(t)
	sessions, errs := awaitAsync(h)

	conn := dial(t, h.Addr)
	sendHello(t, conn, wire.Hello{
		ProtoMin: 1, ProtoMax: 99, Token: h.Token,
		SessionStamp: "s1",
		Capabilities: wire.Capabilities{Signals: []string{"tpm"}, Elevated: true},
	})

	var s *Session
	select {
	case s = <-sessions:
	case err := <-errs:
		t.Fatal(err)
	}
	if s.Version != wire.MaxProtocolVersion {
		t.Fatalf("negotiated %d, want %d", s.Version, wire.MaxProtocolVersion)
	}
	if s.Hello.Token != "" {
		t.Fatal("session retains the bootstrap token")
	}

	// The control channel is a zero-buffer pipe on Windows: a write blocks
	// until the peer reads, so the client's ack read must run concurrently
	// with the server's Ack write — exactly as the two independent processes
	// do in production. Reading after Ack returned on one goroutine would
	// deadlock.
	type acked struct {
		env wire.Envelope
		err error
	}
	ackCh := make(chan acked, 1)
	go func() {
		env, err := wire.NewReader(conn).Read()
		ackCh <- acked{env, err}
	}()

	if err := s.Ack(wire.HelloAck{Mode: wire.ModeObserve}); err != nil {
		t.Fatal(err)
	}
	got := <-ackCh
	if got.err != nil {
		t.Fatal(got.err)
	}
	var ack wire.HelloAck
	if err := wire.Unmarshal(got.env, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Proto != s.Version || ack.Mode != wire.ModeObserve {
		t.Fatalf("ack = %+v", ack)
	}
}

// TestChannelTokenMismatchKillsChild pins the authentication contract: a
// wrong token surfaces as ErrBadToken (the harness's cue to kill the child)
// and the connection is closed before any harness message is sent.
func TestChannelTokenMismatchKillsChild(t *testing.T) {
	h := newHost(t)
	_, errs := awaitAsync(h)

	conn := dial(t, h.Addr)
	sendHello(t, conn, wire.Hello{ProtoMin: 1, ProtoMax: 1, Token: "wrong"})

	if err := <-errs; !errors.Is(err, ErrBadToken) {
		t.Fatalf("want ErrBadToken, got %v", err)
	}
	// The peer sees only a closed connection — no ack, no error detail that
	// would help a token-guessing loop.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := wire.NewReader(conn).Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after bad token = %v, want EOF", err)
	}
}

// TestDisjointVersionRangesRefuseTheSession pins never-run-degraded.
func TestDisjointVersionRangesRefuseTheSession(t *testing.T) {
	h := newHost(t)
	_, errs := awaitAsync(h)

	conn := dial(t, h.Addr)
	sendHello(t, conn, wire.Hello{ProtoMin: 1000, ProtoMax: 2000, Token: h.Token})

	if err := <-errs; !errors.Is(err, ErrNoCommonVersion) {
		t.Fatalf("want ErrNoCommonVersion, got %v", err)
	}
}

// TestUnknownControlMessageIsIgnoredNotFatal pins the tolerance asymmetry:
// an unknown notification is skipped and the loop keeps serving; an unknown
// request gets an "unsupported" error reply instead of a hang.
func TestUnknownControlMessageIsIgnoredNotFatal(t *testing.T) {
	h := newHost(t)
	sessions, errs := awaitAsync(h)

	conn := dial(t, h.Addr)
	sendHello(t, conn, wire.Hello{ProtoMin: 1, ProtoMax: 1, Token: h.Token})
	var s *Session
	select {
	case s = <-sessions:
	case err := <-errs:
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []string
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- s.Serve(slog.New(slog.DiscardHandler), map[string]Handler{
			wire.TypeHeartbeat: func(env wire.Envelope) error {
				mu.Lock()
				defer mu.Unlock()
				seen = append(seen, env.Type)
				return nil
			},
		})
	}()

	// Drain the client side concurrently. The channel is a zero-buffer pipe
	// on Windows, so the server's error reply blocks until the client reads
	// it; if the client were still writing (its heartbeat) instead of
	// reading, the two would deadlock. One persistent reader also avoids
	// losing bytes a fresh reader would leave buffered.
	replies := make(chan wire.Envelope, 8)
	cr := wire.NewReader(conn)
	go func() {
		for {
			env, err := cr.Read()
			if err != nil {
				close(replies)
				return
			}
			replies <- env
		}
	}()

	w := wire.NewWriter(conn)
	write := func(env wire.Envelope) {
		t.Helper()
		if err := w.Write(env); err != nil {
			t.Fatal(err)
		}
	}
	// Unknown notification: must be skipped.
	write(wire.Envelope{V: 1, Type: "future.notification"})
	// Unknown request: must be answered with an error, not dropped.
	write(wire.Envelope{V: 1, Type: "future.request", ID: "q1"})
	// Known type afterward: proves the loop survived both.
	hb, err := wire.Marshal(1, wire.TypeHeartbeat, "", "", wire.Heartbeat{Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	write(hb)

	select {
	case reply, ok := <-replies:
		if !ok {
			t.Fatal("client reader closed before the error reply")
		}
		if reply.Type != "error" || reply.Re != "q1" {
			t.Fatalf("unknown request reply = %+v", reply)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no error reply for the unknown request")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heartbeat after unknown messages never dispatched")
		}
		time.Sleep(2 * time.Millisecond)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("serve after channel close: %v", err)
	}
}
