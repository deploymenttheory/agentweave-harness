// Package control is the harness side of the control channel: it hosts the
// local listener the governed server's servant dials, authenticates the
// first message against the bootstrap token, negotiates a protocol version,
// and then dispatches envelopes.
//
// The transport is platform-split: a named pipe with an SDDL admitting only
// the current user and SYSTEM on Windows, a mode-0700-dir unix socket
// elsewhere (which is also what CI's ubuntu leg exercises). The bootstrap
// contract is two environment variables on the child: AGENTWEAVE_CONTROL_PIPE
// (the address) and AGENTWEAVE_CONTROL_TOKEN (32 random bytes, hex), which
// the server must read and scrub before any tool can observe them.
package control

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/deploymenttheory/agentweave-harness/wire"
)

// Env var names of the bootstrap contract.
const (
	EnvPipe = "AGENTWEAVE_CONTROL_PIPE"
	// EnvToken names the env var carrying the bootstrap token; the name is
	// not itself a secret.
	EnvToken = "AGENTWEAVE_CONTROL_TOKEN" //nolint:gosec // G101: env var name, not a credential
)

// Control-channel errors.
var (
	// ErrBadToken reports a hello whose token does not match. The caller must
	// treat this as fatal for the child.
	ErrBadToken = errors.New("control: hello token mismatch")
	// ErrNotHello reports a first message that is not a hello.
	ErrNotHello = errors.New("control: first message is not hello")
	// ErrNoCommonVersion reports disjoint protocol ranges. The session must
	// be refused, never run degraded.
	ErrNoCommonVersion = errors.New("control: no common protocol version")
	// ErrChannelClosed reports a Request left in flight when the channel ended.
	ErrChannelClosed = errors.New("control: channel closed")
)

// Host owns the listener and the token for one session.
type Host struct {
	Addr  string
	Token string

	ln     net.Listener
	logger *slog.Logger
}

// NewHost creates the platform listener and mints the session token.
func NewHost(logger *slog.Logger) (*Host, error) {
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, fmt.Errorf("control: token: %w", err)
	}
	ln, addr, err := listen()
	if err != nil {
		return nil, err
	}
	return &Host{Addr: addr, Token: hex.EncodeToString(tok), ln: ln, logger: logger}, nil
}

// Close tears the listener down.
func (h *Host) Close() error {
	if err := h.ln.Close(); err != nil {
		return fmt.Errorf("control: close listener: %w", err)
	}
	return nil
}

// Session is an authenticated, version-negotiated servant connection.
type Session struct {
	Hello   wire.Hello
	Version int

	conn net.Conn
	r    *wire.Reader
	w    *wire.Writer

	// pending correlates a harness-originated request id to the caller waiting
	// for its response. Serve delivers a matching `re` here before dispatching
	// by type, so Request and the notification handlers share one read loop.
	pmu     sync.Mutex
	nextID  uint64
	pending map[string]chan wire.Envelope
}

// AwaitServant accepts one connection and runs the hello exchange. It does
// NOT send hello.ack — the caller decides mode and effective config and
// completes the handshake with Session.Ack. A token mismatch returns
// ErrBadToken and the caller must kill the child: an unauthenticated peer on
// the channel means the bootstrap secret leaked or the wrong process dialed.
func (h *Host) AwaitServant(ctx context.Context) (*Session, error) {
	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		conn, err := h.ln.Accept()
		ch <- accepted{conn, err}
	}()

	var conn net.Conn
	select {
	case a := <-ch:
		if a.err != nil {
			return nil, fmt.Errorf("control: accept: %w", a.err)
		}
		conn = a.conn
	case <-ctx.Done():
		_ = h.ln.Close()
		return nil, fmt.Errorf("control: awaiting servant: %w", ctx.Err())
	}

	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(d)
	}
	r := wire.NewReader(conn)
	env, err := r.Read()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("control: reading hello: %w", err)
	}
	if env.Type != wire.TypeHello {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: got %q", ErrNotHello, env.Type)
	}
	var hello wire.Hello
	if err := wire.Unmarshal(env, &hello); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(hello.Token), []byte(h.Token)) != 1 {
		_ = conn.Close()
		return nil, ErrBadToken
	}
	// The token has done its job; do not keep it around to be logged.
	hello.Token = ""

	v, ok := negotiate(hello.ProtoMin, hello.ProtoMax)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: servant [%d,%d], harness [%d,%d]",
			ErrNoCommonVersion, hello.ProtoMin, hello.ProtoMax,
			wire.MinProtocolVersion, wire.MaxProtocolVersion)
	}
	_ = conn.SetReadDeadline(time.Time{})

	return &Session{
		Hello:   hello,
		Version: v,
		conn:    conn,
		r:       r,
		w:       wire.NewWriter(conn),
		pending: map[string]chan wire.Envelope{},
	}, nil
}

// negotiate picks the highest version both ranges admit.
func negotiate(min, max int) (int, bool) {
	v := wire.MaxProtocolVersion
	if max < v {
		v = max
	}
	lo := wire.MinProtocolVersion
	if min > lo {
		lo = min
	}
	if v < lo {
		return 0, false
	}
	return v, true
}

// Ack completes the handshake with the caller's mode and effective config.
func (s *Session) Ack(ack wire.HelloAck) error {
	ack.Proto = s.Version
	env, err := wire.Marshal(s.Version, wire.TypeHelloAck, "", "", ack)
	if err != nil {
		return err
	}
	return s.w.Write(env)
}

// Send writes an envelope, stamping the session's protocol version.
func (s *Session) Send(typ, id, re string, payload any) error {
	env, err := wire.Marshal(s.Version, typ, id, re, payload)
	if err != nil {
		return err
	}
	return s.w.Write(env)
}

// Request sends a harness-originated request and waits for the servant's
// correlated response, which Serve delivers by matching its `re` to this
// request's id. Serve must be running concurrently — it owns the read loop —
// or the response is never routed. A response whose payload is a `{"error":...}`
// object is returned as-is for the caller to interpret.
func (s *Session) Request(ctx context.Context, typ string, payload any) (wire.Envelope, error) {
	s.pmu.Lock()
	s.nextID++
	id := "h" + strconv.FormatUint(s.nextID, 10)
	sink := make(chan wire.Envelope, 1)
	s.pending[id] = sink
	s.pmu.Unlock()

	defer func() {
		s.pmu.Lock()
		delete(s.pending, id)
		s.pmu.Unlock()
	}()

	if err := s.Send(typ, id, "", payload); err != nil {
		return wire.Envelope{}, err
	}
	select {
	case env, ok := <-sink:
		if !ok {
			return wire.Envelope{}, fmt.Errorf("control: request %s: %w", typ, ErrChannelClosed)
		}
		return env, nil
	case <-ctx.Done():
		return wire.Envelope{}, fmt.Errorf("control: request %s: %w", typ, ctx.Err())
	}
}

// deliver routes a response envelope to a waiting Request. It reports whether
// the envelope was a correlated response (and thus consumed).
func (s *Session) deliver(env wire.Envelope) bool {
	if env.Re == "" {
		return false
	}
	s.pmu.Lock()
	sink, ok := s.pending[env.Re]
	if ok {
		delete(s.pending, env.Re)
	}
	s.pmu.Unlock()
	if !ok {
		return false
	}
	sink <- env
	return true
}

// closePending fails any in-flight Request when the channel ends, so a caller
// blocked in Request unblocks rather than waiting for its context.
func (s *Session) closePending() {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	for id, sink := range s.pending {
		close(sink)
		delete(s.pending, id)
	}
}

// Close closes the connection.
func (s *Session) Close() error {
	if err := s.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("control: close session: %w", err)
	}
	return nil
}

// Handler consumes one envelope. Returning an error ends the serve loop —
// reserve it for channel-fatal conditions, not bad payloads.
type Handler func(env wire.Envelope) error

// Serve reads envelopes until the channel closes, dispatching by type.
//
// Tolerance is deliberate and asymmetric, per docs/wire-protocol.md: an
// unknown *notification* type is logged and ignored (a newer servant may
// emit types this harness predates), but an unknown *request* — an envelope
// carrying an id, expecting an answer — gets an error reply so the peer
// fails loudly instead of hanging. io.EOF is a clean channel end.
func (s *Session) Serve(logger *slog.Logger, handlers map[string]Handler) error {
	defer s.closePending()
	for {
		env, err := s.r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("control: serve: %w", err)
		}
		// A correlated response goes to the waiting Request, not a handler.
		if s.deliver(env) {
			continue
		}
		h, ok := handlers[env.Type]
		if !ok {
			if env.ID == "" {
				logger.Warn("control: ignoring unknown notification", "type", env.Type)
				continue
			}
			logger.Warn("control: refusing unknown request", "type", env.Type, "id", env.ID)
			if err := s.Send("error", "", env.ID, map[string]string{
				"error": "unsupported", "type": env.Type,
			}); err != nil {
				return err
			}
			continue
		}
		if err := h(env); err != nil {
			return err
		}
	}
}
