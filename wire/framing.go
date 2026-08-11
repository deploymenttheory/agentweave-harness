package wire

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// MaxLineBytes bounds one JSONL frame. An oversize line is a protocol error
// and tears the channel down: the vocabulary has no message that legitimately
// approaches this size, so exceeding it means a bug or an attempt to wedge
// the reader.
const MaxLineBytes = 256 * 1024

// Framing errors.
var (
	// ErrLineTooLong reports a frame over MaxLineBytes.
	ErrLineTooLong = errors.New("wire: line exceeds MaxLineBytes")
	// ErrMalformed reports a line that is not a valid envelope.
	ErrMalformed = errors.New("wire: malformed envelope")
)

// Reader decodes LF-terminated envelopes from a stream.
type Reader struct {
	r *bufio.Reader
}

// NewReader wraps r for envelope reading.
func NewReader(r io.Reader) *Reader {
	// The buffer must be able to hold a full line: bufio.ReadSlice returns
	// ErrBufferFull past this, which Read converts to ErrLineTooLong.
	return &Reader{r: bufio.NewReaderSize(r, MaxLineBytes)}
}

// Read returns the next envelope. io.EOF is returned as-is so callers can
// treat channel closure distinctly from protocol errors.
func (r *Reader) Read() (Envelope, error) {
	line, err := r.r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return Envelope{}, ErrLineTooLong
		}
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return Envelope{}, io.EOF
		}
		if !errors.Is(err, io.EOF) {
			return Envelope{}, fmt.Errorf("wire: read: %w", err)
		}
		// A final unterminated line at EOF falls through and is parsed.
	}
	var env Envelope
	if uerr := json.Unmarshal(line, &env); uerr != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformed, uerr)
	}
	return env, nil
}

// Writer encodes envelopes as LF-terminated JSONL. It is safe for concurrent
// use: envelopes from different goroutines interleave at line granularity,
// never mid-line.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter wraps w for envelope writing.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write marshals env, stamps TS if unset, and writes one line.
func (w *Writer) Write(env Envelope) error {
	if env.TS == "" {
		env.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("wire: marshal: %w", err)
	}
	if len(b)+1 > MaxLineBytes {
		return ErrLineTooLong
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("wire: write: %w", err)
	}
	return nil
}

// Marshal builds an envelope around a payload struct.
func Marshal(v int, typ, id, re string, payload any) (Envelope, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return Envelope{}, fmt.Errorf("wire: marshal payload: %w", err)
		}
		raw = b
	}
	return Envelope{V: v, Type: typ, ID: id, Re: re, Payload: raw}, nil
}

// Unmarshal decodes an envelope's payload into out.
func Unmarshal(env Envelope, out any) error {
	if err := json.Unmarshal(env.Payload, out); err != nil {
		return fmt.Errorf("%w: %s payload: %w", ErrMalformed, env.Type, err)
	}
	return nil
}
