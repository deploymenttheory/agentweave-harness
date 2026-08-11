package wire

import (
	"bytes"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWireIsStdlibOnly pins the package's import discipline. wire is the one
// contract both the harness and any governed server's servant must share; the
// moment it imports anything beyond the standard library it drags that
// dependency into every implementer and can no longer be split into its own
// module. Enforced here rather than in review because the failure mode is a
// convenience import that looks harmless.
func TestWireIsStdlibOnly(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %q; wire must stay stdlib-only", e.Name(), path)
			}
		}
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	env, err := Marshal(1, TypeHeartbeat, "", "", Heartbeat{Seq: 7, DesktopAlive: true})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := NewWriter(&buf).Write(env); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		t.Fatal("frame is not LF-terminated")
	}

	got, err := NewReader(&buf).Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeHeartbeat || got.V != 1 {
		t.Fatalf("round-trip envelope = %+v", got)
	}
	if got.TS == "" {
		t.Error("writer did not stamp TS")
	}
	var hb Heartbeat
	if err := Unmarshal(got, &hb); err != nil {
		t.Fatal(err)
	}
	if hb.Seq != 7 || !hb.DesktopAlive {
		t.Fatalf("payload = %+v", hb)
	}
}

// TestOversizeLineIsAProtocolError pins the wedge-resistance bound in both
// directions: the reader refuses to buffer past MaxLineBytes and the writer
// refuses to emit a frame the peer would refuse to read.
func TestOversizeLineIsAProtocolError(t *testing.T) {
	big := strings.Repeat("x", MaxLineBytes)
	r := NewReader(strings.NewReader(`{"v":1,"type":"` + big + `"}` + "\n"))
	if _, err := r.Read(); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("reader: want ErrLineTooLong, got %v", err)
	}

	env, err := Marshal(1, TypeCredentialEvent, "", "", CredentialEvent{Kind: big})
	if err != nil {
		t.Fatal(err)
	}
	if werr := NewWriter(io.Discard).Write(env); !errors.Is(werr, ErrLineTooLong) {
		t.Fatalf("writer: want ErrLineTooLong, got %v", werr)
	}
}

func TestMalformedLineIsDistinctFromEOF(t *testing.T) {
	r := NewReader(strings.NewReader("not json\n"))
	if _, err := r.Read(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
	r = NewReader(strings.NewReader(""))
	if _, err := r.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
}

// TestFinalUnterminatedLineIsStillRead covers a peer that dies mid-session
// having flushed a frame without its newline: the frame is not lost.
func TestFinalUnterminatedLineIsStillRead(t *testing.T) {
	r := NewReader(strings.NewReader(`{"v":1,"type":"heartbeat","ts":"t"}`))
	env, err := r.Read()
	if err != nil {
		t.Fatalf("unterminated final line: %v", err)
	}
	if env.Type != TypeHeartbeat {
		t.Fatalf("env = %+v", env)
	}
}
