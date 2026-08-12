// Package proxy is the MCP stdio pump: it sits between an MCP client and the
// governed server, forwarding newline-delimited JSON-RPC frames byte-for-byte
// while observing them, and giving the harness two abilities the transport
// alone would not: injecting its own requests toward the server (with their
// responses routed out of band, never to the client) and — in later phases —
// replacing a frame with a synthesized refusal.
//
// Byte-fidelity is the default and the exception is narrow: the only frames
// ever rewritten are client requests whose id trespasses on the harness's
// reserved namespace (see reservedPrefix), which would otherwise let a client
// collide with an injected request's id and confuse response routing.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// MaxFrameBytes bounds one MCP stdio line. Tool results legitimately carry
// base64 screenshots, so this is far larger than the control channel's limit.
const MaxFrameBytes = 64 * 1024 * 1024

// reservedPrefix marks harness-originated request ids. Client requests whose
// id is a string with this prefix are remapped (and un-mapped on the way
// back) so a collision with an injected request is impossible by
// construction rather than improbable.
const (
	reservedPrefix = "aw:"
	remapPrefix    = "awr:"
)

// ErrFrameTooLong reports a line over MaxFrameBytes on either stream.
var ErrFrameTooLong = errors.New("proxy: frame exceeds MaxFrameBytes")

// errInjectClosed reports Inject after the pump stopped.
var errInjectClosed = errors.New("proxy: pump closed")

// Observer sees every frame. Callbacks run on the pumping goroutine for
// their direction: cheap work only, and no re-entrant Inject calls.
type Observer interface {
	// OnClientFrame sees each client→server frame before forwarding.
	OnClientFrame(raw []byte)
	// OnServerFrame sees each server→client frame before forwarding. Frames
	// consumed as injected-request responses are not reported.
	OnServerFrame(raw []byte)
}

// NopObserver observes nothing.
type NopObserver struct{}

func (NopObserver) OnClientFrame([]byte) {}
func (NopObserver) OnServerFrame([]byte) {}

// Interceptor can refuse a client→server request. For each client frame it
// returns a non-nil response frame to refuse — that frame is written to the
// client verbatim and the request is NOT forwarded to the server — or nil to
// forward normally. This is the seam the policy engine sits on: the governed
// server never sees a request the harness refuses.
//
// Intercept runs on the client→server pump goroutine, so it must not block
// indefinitely; a policy decision that needs to wait (an approval, a signal
// round-trip) is the caller's responsibility to bound.
type Interceptor interface {
	Intercept(raw []byte) []byte
}

// Proxy pumps frames between a client (stdin/stdout of the harness) and a
// server (stdin/stdout of the child process).
type Proxy struct {
	clientIn  io.Reader // frames from the MCP client
	clientOut io.Writer // frames to the MCP client
	serverIn  io.Writer // frames to the governed server
	serverOut io.Reader // frames from the governed server
	obs       Observer

	imu         sync.RWMutex // guards interceptor (swappable while pumping)
	interceptor Interceptor  // nil = never refuse (pure proxy)

	mu            sync.Mutex
	nextID        uint64
	pending       map[string]chan []byte // injected id → response sink
	remapped      map[string]json.RawMessage
	writeMu       sync.Mutex // serializes serverIn writes (pump + Inject)
	clientWriteMu sync.Mutex // serializes clientOut writes (server pump + refusals)
	closed        bool
}

// SetInterceptor installs (or replaces) the refusal seam. It is safe to call
// while Run is pumping — the enforcement decider is built once the servant
// connects, after the pump has started — so a session can begin fail-closed
// and swap to the policy decider without a restart.
func (p *Proxy) SetInterceptor(i Interceptor) {
	p.imu.Lock()
	p.interceptor = i
	p.imu.Unlock()
}

func (p *Proxy) getInterceptor() Interceptor {
	p.imu.RLock()
	defer p.imu.RUnlock()
	return p.interceptor
}

// New builds a proxy over the four streams. obs must not be nil; use
// NopObserver.
func New(clientIn io.Reader, clientOut io.Writer, serverIn io.Writer, serverOut io.Reader, obs Observer) *Proxy {
	return &Proxy{
		clientIn:  clientIn,
		clientOut: clientOut,
		serverIn:  serverIn,
		serverOut: serverOut,
		obs:       obs,
		pending:   map[string]chan []byte{},
		remapped:  map[string]json.RawMessage{},
	}
}

// Run pumps both directions until either stream ends or ctx is canceled.
// A clean client EOF (the MCP host closed stdin) returns nil; anything else
// returns the first error. Both directions stop before Run returns.
func (p *Proxy) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer p.close()

	errs := make(chan error, 2)
	go func() { errs <- p.pumpClientToServer() }()
	go func() { errs <- p.pumpServerToClient() }()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		return fmt.Errorf("proxy: %w", ctx.Err())
	}
}

// Inject sends a harness-originated request to the server and returns the
// raw response frame. The response is consumed by the pump and never reaches
// the client. body is the request WITHOUT an id; Inject assigns one from the
// reserved namespace.
func (p *Proxy) Inject(ctx context.Context, body map[string]any) ([]byte, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errInjectClosed
	}
	p.nextID++
	id := reservedPrefix + strconv.FormatUint(p.nextID, 10)
	sink := make(chan []byte, 1)
	p.pending[id] = sink
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
	}()

	body["id"] = id
	line, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("proxy: marshal injected request: %w", err)
	}
	if err := p.writeServer(append(line, '\n')); err != nil {
		return nil, err
	}

	select {
	case resp := <-sink:
		return resp, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("proxy: injected request %s: %w", id, ctx.Err())
	}
}

func (p *Proxy) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for id, sink := range p.pending {
		close(sink)
		delete(p.pending, id)
	}
}

func (p *Proxy) writeServer(line []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if _, err := p.serverIn.Write(line); err != nil {
		return fmt.Errorf("proxy: write to server: %w", err)
	}
	return nil
}

func (p *Proxy) pumpClientToServer() error {
	r := bufio.NewReaderSize(p.clientIn, 64*1024)
	for {
		line, err := readLine(r)
		if len(line) > 0 {
			p.obs.OnClientFrame(line)
			// The refusal seam runs before forwarding: a refused request is
			// answered to the client and never reaches the server. Observation
			// still happened above, so a refused call is recorded like any other.
			if interceptor := p.getInterceptor(); interceptor != nil {
				if refusal := interceptor.Intercept(line); refusal != nil {
					if werr := p.writeClient(refusal); werr != nil {
						return werr
					}
					goto next
				}
			}
			{
				out, werr := p.forwardClientFrame(line)
				if werr != nil {
					return werr
				}
				if werr := p.writeServer(out); werr != nil {
					return werr
				}
			}
		}
	next:
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// writeClient serializes writes to the client stream between the server→client
// pump and synthesized refusals.
func (p *Proxy) writeClient(line []byte) error {
	p.clientWriteMu.Lock()
	defer p.clientWriteMu.Unlock()
	if _, err := p.clientOut.Write(line); err != nil {
		return fmt.Errorf("proxy: write to client: %w", err)
	}
	return nil
}

// forwardClientFrame returns the bytes to send to the server: the original
// line, except for the reserved-namespace collision case.
func (p *Proxy) forwardClientFrame(line []byte) ([]byte, error) {
	f := peekFrame(line)
	if f.method == "" || f.id == nil {
		// Responses and notifications pass through untouched: ids on the
		// client→server response path belong to the server's own request id
		// space, which the harness never allocates from.
		return line, nil
	}
	var s string
	if err := json.Unmarshal(f.id, &s); err != nil {
		return line, nil // non-string id cannot collide with the namespace
	}
	if !strings.HasPrefix(s, reservedPrefix) {
		return line, nil
	}

	p.mu.Lock()
	p.nextID++
	mapped := remapPrefix + strconv.FormatUint(p.nextID, 10)
	p.remapped[mapped] = f.id
	p.mu.Unlock()

	mappedRaw, err := json.Marshal(mapped)
	if err != nil {
		return nil, fmt.Errorf("proxy: marshal remapped id: %w", err)
	}
	return rewriteID(line, mappedRaw)
}

func (p *Proxy) pumpServerToClient() error {
	r := bufio.NewReaderSize(p.serverOut, 64*1024)
	for {
		line, err := readLine(r)
		if len(line) > 0 {
			forward, out, werr := p.routeServerFrame(line)
			if werr != nil {
				return werr
			}
			if forward {
				p.obs.OnServerFrame(out)
				if werr := p.writeClient(out); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// routeServerFrame decides whether a server→client frame is forwarded, and
// with what bytes: injected-request responses are consumed, responses to
// remapped client requests get their original id back, everything else is
// byte-faithful.
func (p *Proxy) routeServerFrame(line []byte) (forward bool, out []byte, err error) {
	f := peekFrame(line)
	if !f.isResponse || f.id == nil {
		return true, line, nil
	}
	var s string
	if uerr := json.Unmarshal(f.id, &s); uerr != nil {
		return true, line, nil
	}

	p.mu.Lock()
	sink, isInjected := p.pending[s]
	if isInjected {
		delete(p.pending, s)
	}
	orig, isRemapped := p.remapped[s]
	if isRemapped {
		delete(p.remapped, s)
	}
	p.mu.Unlock()

	if isInjected {
		sink <- line
		return false, nil, nil
	}
	if isRemapped {
		restored, rerr := rewriteID(line, orig)
		if rerr != nil {
			return false, nil, rerr
		}
		return true, restored, nil
	}
	return true, line, nil
}

// readLine reads one LF-terminated line including the terminator, enforcing
// MaxFrameBytes. On EOF the final unterminated line (if any) is returned with
// io.EOF.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxFrameBytes {
			return nil, ErrFrameTooLong
		}
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return line, io.EOF
		default:
			return line, fmt.Errorf("proxy: read: %w", err)
		}
	}
}
