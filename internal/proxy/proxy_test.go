package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// collect is an Observer that records copies of every frame it sees.
type collect struct {
	mu     sync.Mutex
	client [][]byte
	server [][]byte
}

func (c *collect) OnClientFrame(raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client = append(c.client, append([]byte(nil), raw...))
}

func (c *collect) OnServerFrame(raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.server = append(c.server, append([]byte(nil), raw...))
}

// run wires a proxy over in-memory pipes and returns hooks for the test to
// play the MCP client and the governed server.
type rig struct {
	proxy *Proxy

	clientToProxy io.WriteCloser // test writes client frames here
	proxyToClient *bytes.Buffer  // frames the client would receive
	serverInbox   *bytes.Buffer  // frames the server received
	serverReply   io.WriteCloser // test writes server frames here

	done chan error
	mu   sync.Mutex
}

func startRig(t *testing.T, obs Observer) *rig {
	t.Helper()
	cIn, cInW := io.Pipe()
	sOut, sOutW := io.Pipe()
	r := &rig{
		clientToProxy: cInW,
		proxyToClient: &bytes.Buffer{},
		serverInbox:   &bytes.Buffer{},
		serverReply:   sOutW,
		done:          make(chan error, 1),
	}
	r.proxy = New(cIn, syncWriter{&r.mu, r.proxyToClient}, syncWriter{&r.mu, r.serverInbox}, sOut, obs)
	go func() { r.done <- r.proxy.Run(context.Background()) }()
	t.Cleanup(func() {
		_ = r.clientToProxy.Close()
		_ = r.serverReply.Close()
	})
	return r
}

// syncWriter serializes buffer access between pump goroutines and the test.
type syncWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (s syncWriter) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(b)
}

func (r *rig) waitFor(t *testing.T, buf *bytes.Buffer, want string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		got := buf.String()
		r.mu.Unlock()
		if strings.Contains(got, want) {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t.Fatalf("timed out waiting for %q in %q", want, buf.String())
	return ""
}

// TestProxyIsByteFaithfulWhenNotIntervening pins the pump's core promise:
// frames it has no reason to touch arrive exactly as sent — key order,
// whitespace, unicode, trailing CR, unparseable lines and all. The moment
// this breaks, evidence gathered on the wire stops describing what the
// client and server actually said.
func TestProxyIsByteFaithfulWhenNotIntervening(t *testing.T) {
	golden := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}`,
		`{"method":"notifications/initialized",  "jsonrpc" : "2.0"}`,
		`{"id": "client-7", "method": "tools/call", "params": {"name": "Snapshot", "unicode": "hélloé"}}`,
		`{"id":"client-7","result":{"content":[{"type":"text","text":"` + strings.Repeat("x", 100_000) + `"}]}}`,
		"not json at all",
		`{"id":42,"result":{"ok":true}}` + "\r",
	}

	obs := &collect{}
	r := startRig(t, obs)

	// Client → server: requests, notifications, junk.
	for _, l := range golden {
		if _, err := io.WriteString(r.clientToProxy, l+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	want := strings.Join(golden, "\n") + "\n"
	if got := r.waitFor(t, r.serverInbox, "\r\n"); got != want {
		t.Fatalf("client→server bytes mutated:\ngot  %q\nwant %q", got, want)
	}

	// Server → client: responses, server-originated requests, junk.
	for _, l := range golden {
		if _, err := io.WriteString(r.serverReply, l+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.waitFor(t, r.proxyToClient, "\r\n"); got != want {
		t.Fatalf("server→client bytes mutated:\ngot  %q\nwant %q", got, want)
	}

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.client) != len(golden) || len(obs.server) != len(golden) {
		t.Fatalf("observer saw %d client / %d server frames, want %d each",
			len(obs.client), len(obs.server), len(golden))
	}
}

// TestInjectedResponsesNeverReachTheClient pins out-of-band routing: the
// response to a harness-injected request is consumed by Inject and the
// client's stream shows no trace of it, while unrelated traffic keeps
// flowing.
func TestInjectedResponsesNeverReachTheClient(t *testing.T) {
	r := startRig(t, NopObserver{})

	type injectResult struct {
		raw []byte
		err error
	}
	res := make(chan injectResult, 1)
	go func() {
		raw, err := r.proxy.Inject(context.Background(), map[string]any{
			"jsonrpc": "2.0", "method": "tools/list",
		})
		res <- injectResult{raw, err}
	}()

	// The server sees the injected request with a reserved-namespace id.
	inbox := r.waitFor(t, r.serverInbox, `"id":"aw:`)
	var req struct {
		ID     string `json:"id"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal([]byte(inbox[:strings.IndexByte(inbox, '\n')]), &req); err != nil {
		t.Fatal(err)
	}
	if req.Method != "tools/list" || !strings.HasPrefix(req.ID, reservedPrefix) {
		t.Fatalf("injected request = %+v", req)
	}

	// Server answers it, then sends an unrelated notification.
	reply := `{"jsonrpc":"2.0","id":"` + req.ID + `","result":{"tools":[]}}`
	marker := `{"jsonrpc":"2.0","method":"notifications/progress"}`
	if _, err := io.WriteString(r.serverReply, reply+"\n"+marker+"\n"); err != nil {
		t.Fatal(err)
	}

	got := <-res
	if got.err != nil {
		t.Fatal(got.err)
	}
	if !strings.Contains(string(got.raw), `"tools":[]`) {
		t.Fatalf("Inject returned %q", got.raw)
	}

	out := r.waitFor(t, r.proxyToClient, "notifications/progress")
	if strings.Contains(out, req.ID) {
		t.Fatalf("injected response leaked to the client: %q", out)
	}
}

// TestInjectedRequestIdsNeverCollideWithClientIds pins the collision defense:
// a client request that trespasses on the reserved id namespace is remapped
// before the server sees it, the server's response is un-mapped so the
// client sees its own id again, and a concurrent injected request with a
// colliding-looking id still routes to Inject, not the client.
func TestInjectedRequestIdsNeverCollideWithClientIds(t *testing.T) {
	r := startRig(t, NopObserver{})

	// The client (adversarially or by miracle) uses a reserved-prefix id.
	hostile := `{"jsonrpc":"2.0","id":"aw:1","method":"tools/call","params":{"name":"Shell"}}`
	if _, err := io.WriteString(r.clientToProxy, hostile+"\n"); err != nil {
		t.Fatal(err)
	}

	inbox := r.waitFor(t, r.serverInbox, `"awr:`)
	if strings.Contains(inbox, `"aw:1"`) {
		t.Fatalf("reserved-namespace client id reached the server verbatim: %q", inbox)
	}
	var fwd struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(inbox[:strings.IndexByte(inbox, '\n')]), &fwd); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fwd.ID, remapPrefix) {
		t.Fatalf("remapped id = %q", fwd.ID)
	}

	// The server answers the remapped id; the client must get "aw:1" back.
	if _, err := io.WriteString(r.serverReply,
		`{"jsonrpc":"2.0","id":"`+fwd.ID+`","result":{"ok":true}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	out := r.waitFor(t, r.proxyToClient, `"ok":true`)
	if !strings.Contains(out, `"aw:1"`) {
		t.Fatalf("client did not get its original id back: %q", out)
	}
	if strings.Contains(out, remapPrefix) {
		t.Fatalf("remapped id leaked to the client: %q", out)
	}
}

// TestClientResponsesToServerRequestsPassThrough covers the other JSON-RPC
// direction: a server→client request's id belongs to the server's own id
// space, so the client's response — even one whose id looks reserved — must
// pass through untouched.
func TestClientResponsesToServerRequestsPassThrough(t *testing.T) {
	r := startRig(t, NopObserver{})

	serverReq := `{"jsonrpc":"2.0","id":"aw:9","method":"roots/list"}`
	if _, err := io.WriteString(r.serverReply, serverReq+"\n"); err != nil {
		t.Fatal(err)
	}
	if got := r.waitFor(t, r.proxyToClient, "roots/list"); !strings.Contains(got, `"aw:9"`) {
		t.Fatalf("server request mutated: %q", got)
	}

	clientResp := `{"jsonrpc":"2.0","id":"aw:9","result":{"roots":[]}}`
	if _, err := io.WriteString(r.clientToProxy, clientResp+"\n"); err != nil {
		t.Fatal(err)
	}
	if got := r.waitFor(t, r.serverInbox, `"roots":[]`); !strings.Contains(got, clientResp) {
		t.Fatalf("client response mutated: %q", got)
	}
}

// refuseTools is an Interceptor that refuses any tools/call with a canned
// frame and forwards everything else.
type refuseTools struct{ refusal string }

func (r refuseTools) Intercept(raw []byte) []byte {
	if strings.Contains(string(raw), `"tools/call"`) {
		return []byte(r.refusal + "\n")
	}
	return nil
}

// TestInterceptorRefusalReplacesTheRequest pins the enforcement seam at the
// pump: a refused request is answered to the client and never reaches the
// server, while an allowed request flows through to the server as normal.
func TestInterceptorRefusalReplacesTheRequest(t *testing.T) {
	r := startRig(t, NopObserver{})
	r.proxy.SetInterceptor(refuseTools{refusal: `{"jsonrpc":"2.0","id":"c1","result":{"isError":true}}`})

	// A tools/call: refused. The client gets the refusal; the server sees nothing.
	if _, err := io.WriteString(r.clientToProxy,
		`{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"Shell"}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	out := r.waitFor(t, r.proxyToClient, `"isError":true`)
	if !strings.Contains(out, `"c1"`) {
		t.Fatalf("refusal not returned to client: %q", out)
	}

	// An allowed request (tools/list): forwarded to the server.
	if _, err := io.WriteString(r.clientToProxy,
		`{"jsonrpc":"2.0","id":"c2","method":"tools/list"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	inbox := r.waitFor(t, r.serverInbox, "tools/list")
	if strings.Contains(inbox, "tools/call") {
		t.Fatalf("refused request leaked to the server: %q", inbox)
	}
}

// TestClientEOFEndsTheRunCleanly pins the shutdown shape: the MCP host
// closing stdin is the normal end of a session, not an error.
func TestClientEOFEndsTheRunCleanly(t *testing.T) {
	r := startRig(t, NopObserver{})
	if err := r.clientToProxy.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("client EOF: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on client EOF")
	}
}

// staticInjector appends fixed tools to every tools/list result.
type staticInjector struct{ tools []json.RawMessage }

func (s staticInjector) Tools() []json.RawMessage { return s.tools }

// TestToolInjectionAppendsToTheClientsManifest pins the response-side
// injection: a tools/list the client requested comes back with the harness's
// tools appended, the server's own tools preserved, and the observer sees the
// combined surface (so the fingerprint baseline is the manifest the client
// sees). A tools/list the client did not request — an out-of-band one — is
// untouched.
func TestToolInjectionAppendsToTheClientsManifest(t *testing.T) {
	obs := &collect{}
	r := startRig(t, obs)
	r.proxy.SetToolInjector(staticInjector{tools: []json.RawMessage{
		json.RawMessage(`{"name":"GuardrailStatus"}`),
	}})

	// Client asks for tools/list.
	if _, err := io.WriteString(r.clientToProxy,
		`{"jsonrpc":"2.0","id":"t1","method":"tools/list"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	// Wait until the request has been forwarded to the server before the server
	// answers: in production the request always passes through the proxy (and
	// is noted for injection) before the server can reply, so replying earlier
	// is a race only this in-memory rig could create.
	r.waitFor(t, r.serverInbox, `"tools/list"`)
	// Server answers with one tool.
	if _, err := io.WriteString(r.serverReply,
		`{"jsonrpc":"2.0","id":"t1","result":{"tools":[{"name":"Snapshot"}]}}`+"\n"); err != nil {
		t.Fatal(err)
	}

	got := r.waitFor(t, r.proxyToClient, "GuardrailStatus")
	if !strings.Contains(got, "Snapshot") {
		t.Fatalf("the server's own tool was dropped:\n%s", got)
	}
	// The observer must have seen the injected surface, not the raw one.
	obs.mu.Lock()
	serverFrames := append([][]byte(nil), obs.server...)
	obs.mu.Unlock()
	if !containsFrame(serverFrames, "GuardrailStatus") {
		t.Fatal("the observer fingerprinted the pre-injection surface; the injected tools are outside the baseline")
	}
}

// containsFrame reports whether any observed frame contains want.
func containsFrame(frames [][]byte, want string) bool {
	for _, f := range frames {
		if strings.Contains(string(f), want) {
			return true
		}
	}
	return false
}
