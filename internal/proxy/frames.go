package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// frame is the peek view of one MCP stdio line: enough JSON-RPC structure to
// route it, without touching the bytes that get forwarded. raw retains the
// exact line (newline included) so the pump stays byte-faithful whenever it
// does not have to intervene.
type frame struct {
	raw []byte

	// id is the raw JSON of the "id" member, nil when absent (notification).
	id json.RawMessage
	// method is set on requests and notifications, empty on responses.
	method string
	// isResponse reports a result or error member — a JSON-RPC response.
	isResponse bool
}

// peekFrame parses just the routing fields. A line that is not JSON at all is
// returned with zero routing info and forwarded untouched — the harness is a
// proxy first; deciding whether malformed traffic should be refused is the
// enforcement layer's job (a later phase), not the pump's.
func peekFrame(line []byte) frame {
	f := frame{raw: line}
	var probe struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(line), &probe); err != nil {
		return f
	}
	f.id = probe.ID
	f.method = probe.Method
	f.isResponse = probe.Method == "" && (probe.Result != nil || probe.Error != nil)
	return f
}

// rewriteID re-marshals the frame with a replacement "id". This is the one
// operation that gives up byte-fidelity, so it is reserved for the collision
// path: a client request whose id trespasses on the harness's reserved
// namespace. Key order is not preserved; JSON-RPC gives no meaning to it.
func rewriteID(line []byte, newID json.RawMessage) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(line), &obj); err != nil {
		return nil, fmt.Errorf("proxy: rewrite id: %w", err)
	}
	obj["id"] = newID
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("proxy: rewrite id: %w", err)
	}
	return append(out, '\n'), nil
}
