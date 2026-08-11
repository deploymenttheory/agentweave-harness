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
	for {
		env, err := s.r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("control: serve: %w", err)
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
