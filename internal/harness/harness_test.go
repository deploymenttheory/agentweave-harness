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
// authenticates, gets an observe-mode ack, and MCP traffic still flows.
func TestRunAcceptsAServantAndStaysTransparent(t *testing.T) {
	in, out, done := runHarness(t, "servant")

	if _, err := io.WriteString(in, `{"jsonrpc":"2.0","id":7,"method":"ping"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	waitContains(t, out, `"echo":true`)
	drainClean(t, in, done)
}
