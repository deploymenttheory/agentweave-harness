package inject

import (
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/agentweave-harness/internal/proxy"
)

// Interceptor answers calls to the injected tools and delegates everything
// else. It sits outermost on the proxy's refusal seam: a tools/call for
// GuardrailStatus or Kill is answered here — a success result written to the
// client, never forwarded to the server, which does not have the tool — and
// any other frame passes to the delegate (the policy decider). Answering an
// injected tool is not subject to the policy engine: these are the harness's
// own tools, and refusing the client's window into the harness posture, or its
// ability to stop the session, would be perverse.
type Interceptor struct {
	inj      *Injector
	delegate proxy.Interceptor
}

// WrapInterceptor puts the injected-tool answering in front of delegate.
func WrapInterceptor(inj *Injector, delegate proxy.Interceptor) *Interceptor {
	return &Interceptor{inj: inj, delegate: delegate}
}

type callFrame struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// Intercept answers an injected-tool call, else delegates.
func (i *Interceptor) Intercept(raw []byte) []byte {
	var f callFrame
	if json.Unmarshal(raw, &f) == nil &&
		f.Method == "tools/call" && len(f.ID) > 0 && string(f.ID) != "null" &&
		i.inj.Answers(f.Params.Name) {
		text, _ := i.inj.Answer(f.Params.Name, f.Params.Arguments)
		if frame, err := toolResultFrame(f.ID, text); err == nil {
			return frame
		}
		// Fall through to the delegate on a marshal failure rather than drop
		// the call silently — the delegate will at least refuse or forward it.
	}
	if i.delegate == nil {
		return nil
	}
	return i.delegate.Intercept(raw)
}

// toolResultFrame builds a successful tools/call result carrying the text.
func toolResultFrame(id json.RawMessage, text string) ([]byte, error) {
	result := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
	rb, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("inject: marshal result: %w", err)
	}
	frame, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "result": json.RawMessage(rb),
	})
	if err != nil {
		return nil, fmt.Errorf("inject: marshal frame: %w", err)
	}
	return append(frame, '\n'), nil
}

// Ensure Interceptor satisfies the proxy seam.
var _ proxy.Interceptor = (*Interceptor)(nil)
