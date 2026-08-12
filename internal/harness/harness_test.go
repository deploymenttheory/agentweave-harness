package harness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deploymenttheory/agentweave-harness/internal/control"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// TestMain doubles this test binary as the fake governed server, the
// standard helper-process pattern: Run spawns os.Executable() and the child
// sees AW_FAKE_SERVER in its inherited environment.
func TestMain(m *testing.M) {
	switch os.Getenv("AW_FAKE_SERVER") {
	case "":
		os.Exit(m.Run())
	case "echo":
		fakeServerEcho()
	case "servant":
		fakeServerServant()
	case "signal-servant":
		fakeSignalServant()
	}
}

// fakeSignalServant dials the control channel advertising a "tpm" signal, then
// answers every signal.evaluate with a FAILING result for the requested ids —
// enough for the harness's policy engine to deny a rule that requires tpm. It
// serves stdio concurrently, like a real Phase-3 server.
func fakeSignalServant() {
	conn, err := control.Dial(os.Getenv(control.EnvPipe))
	if err != nil {
		os.Exit(3)
	}
	w := wire.NewWriter(conn)
	hello, _ := wire.Marshal(1, wire.TypeHello, "", "", wire.Hello{
		ProtoMin: wire.MinProtocolVersion, ProtoMax: wire.MaxProtocolVersion,
		Token: os.Getenv(control.EnvToken), SessionStamp: "fake",
		Capabilities: wire.Capabilities{Signals: []string{"tpm"}},
	})
	if err := w.Write(hello); err != nil {
		os.Exit(3)
	}
	r := wire.NewReader(conn)
	ack, err := r.Read()
	if err != nil || ack.Type != wire.TypeHelloAck {
		os.Exit(4)
	}
	reportAckMode(ack)
	// Answer control requests: a signal.evaluate gets a failing result per id.
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
				results = append(results, json.RawMessage(
					`{"id":"`+id+`","status":"fail","detail":"tpm absent"}`))
			}
			reply, _ := wire.Marshal(1, wire.TypeSignalResult, "", env.ID, wire.SignalResult{Results: results})
			_ = w.Write(reply)
		}
	}()
	fakeServerEcho()
}

// ackModeFileEnv names a file the fake servant writes the hello.ack's mode
// into, so a test can assert which mode the harness actually told its server —
// the wire fact the shedding contract rests on — without touching the MCP
// stream.
const ackModeFileEnv = "AW_ACK_MODE_FILE"

// reportAckMode writes the ack's mode to the file named by ackModeFileEnv, if
// the driving test asked for it.
func reportAckMode(ack wire.Envelope) {
	path := os.Getenv(ackModeFileEnv)
	if path == "" {
		return
	}
	var ha wire.HelloAck
	if err := wire.Unmarshal(ack, &ha); err != nil {
		os.Exit(5)
	}
	if err := os.WriteFile(path, []byte(ha.Mode), 0o600); err != nil {
		os.Exit(5)
	}
}

// fakeServerEcho is a pre-Phase-3 server: speaks MCP-ish stdio only, never
// dials the control channel. It answers every request line with a canned
// response carrying the same id, and exits on stdin EOF.
func fakeServerEcho() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		var probe struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(sc.Bytes(), &probe); err != nil || probe.ID == nil {
			continue
		}
		_, _ = os.Stdout.WriteString(`{"jsonrpc":"2.0","id":` + string(probe.ID) + `,"result":{"echo":true}}` + "\n")
	}
	os.Exit(0)
}

// fakeServerServant additionally dials the control channel like a Phase-3
// server: hello with the bootstrap token, then one heartbeat after the ack.
func fakeServerServant() {
	conn, err := control.Dial(os.Getenv(control.EnvPipe))
	if err != nil {
		os.Exit(3)
	}
	w := wire.NewWriter(conn)
	env, err := wire.Marshal(1, wire.TypeHello, "", "", wire.Hello{
		ProtoMin: wire.MinProtocolVersion, ProtoMax: wire.MaxProtocolVersion,
		Token: os.Getenv(control.EnvToken), SessionStamp: "fake",
	})
	if err != nil {
		os.Exit(3)
	}
	if err := w.Write(env); err != nil {
		os.Exit(3)
	}
	ack, err := wire.NewReader(conn).Read()
	if err != nil || ack.Type != wire.TypeHelloAck {
		os.Exit(4)
	}
	hb, err := wire.Marshal(1, wire.TypeHeartbeat, "", "", wire.Heartbeat{Seq: 1, DesktopAlive: true})
	if err == nil {
		_ = w.Write(hb)
	}
	// Hold the channel open while serving stdio, as a real servant would.
	fakeServerEcho()
}

// runHarness starts Run against the helper in the given mode and returns
// the client-side hooks. t.Setenv makes the mode visible to the child via
// the inherited environment.
func runHarness(t *testing.T, mode string) (io.WriteCloser, *lockedBuffer, chan error) {
	return runHarnessCfg(t, mode, Config{})
}

// runHarnessCfg is runHarness with caller-supplied Config overrides (Argv,
// Logger and the client streams are always set here).
func runHarnessCfg(t *testing.T, mode string, cfg Config) (io.WriteCloser, *lockedBuffer, chan error) {
	t.Helper()
	t.Setenv("AW_FAKE_SERVER", mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	out := &lockedBuffer{}
	cfg.Argv = []string{exe}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	cfg.ClientIn = inR
	cfg.ClientOut = out
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), cfg) }()
	t.Cleanup(func() { _ = inW.Close() })
	return inW, out, done
}

// TestRunAuditsProxiedToolCalls covers the observe layer end to end: a real
// child process, a tools/call over the proxy, and the harness's own audit
// chain (written to a temp file) carrying a tool.call record — with no raw
// argument value in it.
func TestRunAuditsProxiedToolCalls(t *testing.T) {
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	in, out, done := runHarnessCfg(t, "echo", Config{AuditSink: auditFile})

	call := `{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"Type","arguments":{"text":"topsecret"}}}`
	if _, err := io.WriteString(in, call+"\n"); err != nil {
		t.Fatal(err)
	}
	waitContains(t, out, `"echo":true`)
	drainClean(t, in, done)

	b, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	chain := string(b)
	if !strings.Contains(chain, `"event":"tool.call"`) {
		t.Fatalf("audit chain has no tool.call:\n%s", chain)
	}
	if strings.Contains(chain, "topsecret") {
		t.Fatalf("raw argument value leaked into the audit chain:\n%s", chain)
	}
}

// TestRunEnforcesPolicyOverTheChannel is the Phase-4b end-to-end pin: an
// enforcing policy whose rule requires a signal the servant reports as failing
// causes the harness to refuse the tool call on the wire — the client gets an
// IsError result and the server (the echo half) never sees the call.
func TestRunEnforcesPolicyOverTheChannel(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policyDoc := `{
	  "version": 1,
	  "mode": "enforce",
	  "signals": {"tpm": {"ttl": "0s"}},
	  "rules": [
	    {"name": "shell-needs-tpm", "match": {"tool": "Shell"}, "require": ["tpm"], "on_fail": "deny"}
	  ]
	}`
	if err := os.WriteFile(policyPath, []byte(policyDoc), 0o600); err != nil {
		t.Fatal(err)
	}

	ackFile := filepath.Join(t.TempDir(), "ackmode")
	t.Setenv(ackModeFileEnv, ackFile)
	in, out, done := runHarnessCfg(t, "signal-servant", Config{PolicyConfig: policyPath})

	// Give the servant a moment to connect and enforcement to activate, so the
	// call is decided rather than caught by the fail-closed initializer (either
	// way it is refused; this asserts the policy path specifically).
	call := `{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"Shell","arguments":{"cmd":"whoami"}}}`
	if _, err := io.WriteString(in, call+"\n"); err != nil {
		t.Fatal(err)
	}

	got := waitContains(t, out, `"c1"`)
	if !strings.Contains(got, `"isError":true`) {
		t.Fatalf("tools/call was not refused with an IsError result:\n%s", got)
	}
	// The echo server answers with {"echo":true}; a refused call must not have
	// reached it.
	if strings.Contains(got, `"echo":true`) {
		t.Fatalf("refused call reached the server (saw echo):\n%s", got)
	}
	// The enforcement the client just observed must also have been announced to
	// the server: this session's ack is the license to shed.
	if mode := waitAckMode(t, ackFile); mode != wire.ModeEnforce {
		t.Fatalf("harness enforced on the wire but acked mode %q", mode)
	}
	drainClean(t, in, done)
}

// TestAckIsEnforceOnlyWhenDeciderInstalled pins the honest-ack invariant: the
// hello.ack says `enforce` exactly when the harness installed a live policy
// decider — not whenever the document asks for enforcement. An audit-mode
// document refuses nothing, and a document naming a signal the servant cannot
// evaluate never activates, so both must ack observe; the server keeps its
// local stack in each case.
func TestAckIsEnforceOnlyWhenDeciderInstalled(t *testing.T) {
	cases := []struct {
		name       string
		policyMode string
		signal     string // the id the policy requires; the servant serves "tpm"
		want       string
	}{
		{"enforcing policy with servable signals", "enforce", "tpm", wire.ModeEnforce},
		{"audit-mode policy never licenses shedding", "audit", "tpm", wire.ModeObserve},
		{"unservable signal leaves the ack observe", "enforce", "bitlocker", wire.ModeObserve},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policyPath := filepath.Join(t.TempDir(), "policy.json")
			policyDoc := `{
			  "version": 1,
			  "mode": "` + tc.policyMode + `",
			  "signals": {"` + tc.signal + `": {"ttl": "0s"}},
			  "rules": [
			    {"name": "r", "match": {"tool": "Shell"}, "require": ["` + tc.signal + `"], "on_fail": "deny"}
			  ]
			}`
			if err := os.WriteFile(policyPath, []byte(policyDoc), 0o600); err != nil {
				t.Fatal(err)
			}
			ackFile := filepath.Join(t.TempDir(), "ackmode")
			t.Setenv(ackModeFileEnv, ackFile)
			in, out, done := runHarnessCfg(t, "signal-servant", Config{PolicyConfig: policyPath})

			if mode := waitAckMode(t, ackFile); mode != tc.want {
				t.Fatalf("acked mode %q, want %q", mode, tc.want)
			}
			// The unactivated-enforcing session must still be fail-closed: the
			// DenyAll installed before the pump keeps refusing decidable calls,
			// it just never licenses the server to shed.
			if tc.policyMode == "enforce" && tc.want == wire.ModeObserve {
				call := `{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"Shell","arguments":{}}}`
				if _, err := io.WriteString(in, call+"\n"); err != nil {
					t.Fatal(err)
				}
				got := waitContains(t, out, `"c1"`)
				if !strings.Contains(got, `"isError":true`) {
					t.Fatalf("fail-closed session answered a decidable call:\n%s", got)
				}
			}
			drainClean(t, in, done)
		})
	}
}

// waitAckMode polls for the fake servant's record of the hello.ack mode. The
// ack happens during session startup, concurrently with the test body.
func waitAckMode(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the servant to record the acked mode")
	return ""
}

// writeSessionManifest writes a manifest document for a test session.
func writeSessionManifest(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestUndeclaredToolGetsTypedRefusal is the manifest pin end to end: a
// manifest-only session (no policy layers, no servant) refuses a tools/call
// outside allow.tools with the typed permission_denied code, the refused call
// never reaches the server, and a granted call flows through untouched.
func TestUndeclaredToolGetsTypedRefusal(t *testing.T) {
	path := writeSessionManifest(t,
		`{"version": 1, "expires_after": "1h", "allow": {"tools": ["Snapshot"]}}`)
	in, out, done := runHarnessCfg(t, "echo", Config{SessionManifest: path})

	call := `{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"Shell","arguments":{}}}`
	if _, err := io.WriteString(in, call+"\n"); err != nil {
		t.Fatal(err)
	}
	got := waitContains(t, out, `"c1"`)
	if !strings.Contains(got, `"isError":true`) || !strings.Contains(got, "permission_denied") {
		t.Fatalf("undeclared tool was not refused with the typed code:\n%s", got)
	}
	if strings.Contains(got, `"echo":true`) {
		t.Fatalf("refused call reached the server:\n%s", got)
	}

	granted := `{"jsonrpc":"2.0","id":"c2","method":"tools/call","params":{"name":"Snapshot","arguments":{}}}`
	if _, err := io.WriteString(in, granted+"\n"); err != nil {
		t.Fatal(err)
	}
	if got := waitContains(t, out, `"c2"`); !strings.Contains(got, `"echo":true`) {
		t.Fatalf("granted tool did not flow through:\n%s", got)
	}
	drainClean(t, in, done)
}

// TestResourceOutsideManifestIsTypedJSONRPCError pins the other refusal shape:
// a resources/read outside the grant is a JSON-RPC error carrying the typed
// code as structured data, so a client can match on it without parsing prose.
func TestResourceOutsideManifestIsTypedJSONRPCError(t *testing.T) {
	path := writeSessionManifest(t,
		`{"version": 1, "expires_after": "1h", "allow": {"resources": {"files": ["C:\\work"]}}}`)
	in, out, done := runHarnessCfg(t, "echo", Config{SessionManifest: path})

	read := `{"jsonrpc":"2.0","id":"r1","method":"resources/read","params":{"uri":"file:///C:/secrets/key.pem"}}`
	if _, err := io.WriteString(in, read+"\n"); err != nil {
		t.Fatal(err)
	}
	got := waitContains(t, out, `"r1"`)
	if !strings.Contains(got, `"error"`) ||
		!strings.Contains(got, `"data":{"code":"bounded_resource_outside_manifest"}`) {
		t.Fatalf("out-of-grant read was not a typed JSON-RPC error:\n%s", got)
	}
	drainClean(t, in, done)
}

// TestExpiredManifestDrainsTheSession pins expiry end to end: past
// expires_after every decidable request gets session_expired in the method's
// shape — the session drains rather than being killed, so the pump and the
// child stay up.
func TestExpiredManifestDrainsTheSession(t *testing.T) {
	path := writeSessionManifest(t, `{"version": 1, "expires_after": "1ms"}`)
	in, out, done := runHarnessCfg(t, "echo", Config{SessionManifest: path})

	time.Sleep(20 * time.Millisecond) // comfortably past the 1ms grant
	call := `{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"Anything","arguments":{}}}`
	if _, err := io.WriteString(in, call+"\n"); err != nil {
		t.Fatal(err)
	}
	got := waitContains(t, out, `"c1"`)
	if !strings.Contains(got, `"isError":true`) || !strings.Contains(got, "session_expired") {
		t.Fatalf("expired session did not refuse with the typed code:\n%s", got)
	}
	drainClean(t, in, done)
}

// TestRunEnforcesArgumentConstraints pins constraints end to end: a rule
// bounding an argument refuses the oversized call on the wire with the
// argument named — and the value absent — in the refusal, while the compliant
// call flows through.
func TestRunEnforcesArgumentConstraints(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policyDoc := `{
	  "version": 1,
	  "mode": "enforce",
	  "signals": {},
	  "rules": [
	    {"name": "bounded-shell", "match": {"tool": "Shell"}, "require": [],
	     "constraints": {"cmd": {"max_length": 8}}, "on_fail": "deny"}
	  ]
	}`
	if err := os.WriteFile(policyPath, []byte(policyDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	ackFile := filepath.Join(t.TempDir(), "ackmode")
	t.Setenv(ackModeFileEnv, ackFile)
	in, out, done := runHarnessCfg(t, "signal-servant", Config{PolicyConfig: policyPath})

	// The ack is sent only after the real decider is installed (the honest-ack
	// ordering), so waiting for it removes the race against the fail-closed
	// initializer — this test asserts the constraint path specifically.
	if mode := waitAckMode(t, ackFile); mode != wire.ModeEnforce {
		t.Fatalf("expected an enforce ack, got %q", mode)
	}

	longCmd := strings.Repeat("x", 64)
	call := `{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"Shell","arguments":{"cmd":"` +
		longCmd + `"}}}`
	if _, err := io.WriteString(in, call+"\n"); err != nil {
		t.Fatal(err)
	}
	got := waitContains(t, out, `"c1"`)
	if !strings.Contains(got, `"isError":true`) || !strings.Contains(got, "max_length") {
		t.Fatalf("oversized argument was not refused with the bound named:\n%s", got)
	}
	// The client-bound stream carries only the harness's frames, so the value
	// appearing anywhere in it means the refusal leaked the argument back.
	if strings.Contains(got, longCmd) {
		t.Fatal("the argument value leaked into the refusal")
	}

	ok := `{"jsonrpc":"2.0","id":"c2","method":"tools/call","params":{"name":"Shell","arguments":{"cmd":"whoami"}}}`
	if _, err := io.WriteString(in, ok+"\n"); err != nil {
		t.Fatal(err)
	}
	if got := waitContains(t, out, `"c2"`); !strings.Contains(got, `"echo":true`) {
		t.Fatalf("compliant call did not flow through:\n%s", got)
	}
	drainClean(t, in, done)
}

// TestInvalidManagedPolicyPathRefusesToStart pins the fleet-operator
// guarantee: AGENTWEAVE_MANAGED_POLICY naming an unloadable file is a hard
// startup error, never a silent fallback to unmanaged.
func TestInvalidManagedPolicyPathRefusesToStart(t *testing.T) {
	t.Setenv(EnvManagedPolicy, filepath.Join(t.TempDir(), "does-not-exist.json"))
	_, _, done := runHarnessCfg(t, "echo", Config{})
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an unreadable managed policy did not refuse to start")
		}
		if !strings.Contains(err.Error(), EnvManagedPolicy) {
			t.Fatalf("the error does not name the env var the operator must fix: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return on an unreadable managed policy")
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitContains(t *testing.T, b *lockedBuffer, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s := b.String(); strings.Contains(s, want) {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in %q", want, b.String())
	return ""
}

func drainClean(t *testing.T, in io.WriteCloser, done chan error) {
	t.Helper()
	_ = in.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("session end: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after client EOF")
	}
}

// TestRunProxiesARealChildProcess covers the full plumbing: spawn, both
// pumps, the child's answer arriving with its id intact, and a clean exit
// on client EOF.
func TestRunProxiesARealChildProcess(t *testing.T) {
	in, out, done := runHarness(t, "echo")

	if _, err := io.WriteString(in, `{"jsonrpc":"2.0","id":"q-1","method":"tools/list"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	got := waitContains(t, out, `"echo":true`)
	if !strings.Contains(got, `"q-1"`) {
		t.Fatalf("response id mangled: %q", got)
	}
	drainClean(t, in, done)
}

// TestRunAcceptsAServantAndStaysTransparent covers the Phase-3 handshake
// path end to end over the real platform transport: the child dials,
// authenticates, gets an observe-mode ack (no policy is configured, so no
// decider is installed), and MCP traffic still flows.
func TestRunAcceptsAServantAndStaysTransparent(t *testing.T) {
	in, out, done := runHarness(t, "servant")

	if _, err := io.WriteString(in, `{"jsonrpc":"2.0","id":7,"method":"ping"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	waitContains(t, out, `"echo":true`)
	drainClean(t, in, done)
}
