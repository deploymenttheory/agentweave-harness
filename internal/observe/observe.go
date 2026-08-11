// Package observe is the harness's read-only view of the proxied MCP
// conversation. It implements proxy.Observer: every client→server and
// server→client frame passes through it, and from that stream alone it
// maintains the three things the harness can derive without asking the server
// anything — an authoritative audit chain of the decidable methods, rug-pull
// fingerprints of the advertised manifest, and a tool index for the policy
// engine.
//
// This is the observe half of moving adjudication out of the server. It records
// and detects; it refuses nothing (that is the enforcing half, wired on top of
// this same seam). Because the harness sits on the wire, the audit chain and
// the fingerprints describe exactly what the client and server actually
// exchanged — not the server's own account of it.
package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/watch"
)

// maxRecordedString bounds client-supplied text reaching the chain, matching
// the in-process audit middleware: the chain is append-only and a client
// chooses these bytes.
const maxRecordedString = 256

// Observer records and fingerprints the proxied frames. It is safe for
// concurrent use: the two pump directions call it from different goroutines.
type Observer struct {
	audit  *audit.AuditLog
	rp     *watch.RugPull
	logger *slog.Logger

	mu sync.Mutex
	// pending correlates an outstanding request id to its method, so a response
	// frame (which carries no method) can be attributed. Cleared on response.
	pending map[string]string
	// index is the latest tool manifest, kept for the policy engine (Phase 4b).
	index map[string]policy.ToolFacts
	// seenSurfaces records which manifest surfaces have a pinned baseline. A
	// first sighting pins; later sightings recheck.
	seenSurfaces map[string]bool
}

// New builds an observer over an audit log and a rug-pull detector. Either may
// be nil in tests; a nil rug-pull disables fingerprinting, a nil audit disables
// recording.
func New(a *audit.AuditLog, rp *watch.RugPull, logger *slog.Logger) *Observer {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Observer{
		audit: a, rp: rp, logger: logger,
		pending: map[string]string{},
		index:   map[string]policy.ToolFacts{},
	}
}

// jsonrpcFrame is the minimal shape needed to route a frame.
type jsonrpcFrame struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// OnClientFrame records a client→server request. Requests are correlated so the
// matching response can be attributed, and the decidable methods are audited
// with arguments digested, never stored raw.
func (o *Observer) OnClientFrame(raw []byte) {
	var f jsonrpcFrame
	if json.Unmarshal(raw, &f) != nil {
		return
	}
	if f.Method == "" {
		return // a response from the client to a server request; not ours to record
	}
	if len(f.ID) > 0 && string(f.ID) != "null" {
		o.mu.Lock()
		o.pending[string(f.ID)] = f.Method
		o.mu.Unlock()
	}
	o.record(f.Method, f.Params)
}

// OnServerFrame attributes a server→client response to its request's method and,
// for the manifest surfaces, fingerprints it.
func (o *Observer) OnServerFrame(raw []byte) {
	var f jsonrpcFrame
	if json.Unmarshal(raw, &f) != nil {
		return
	}
	if f.Method != "" || len(f.ID) == 0 {
		return // server-originated request or notification; no result to fingerprint
	}
	o.mu.Lock()
	method := o.pending[string(f.ID)]
	delete(o.pending, string(f.ID))
	o.mu.Unlock()
	if method == "" || len(f.Result) == 0 {
		return
	}
	o.fingerprint(method, f.Result)
}

// FingerprintInjected feeds an out-of-band re-list response — one the harness
// asked for itself via proxy.Inject, which the client never sees — through the
// same fingerprint path. It is how drift is caught between client re-lists.
func (o *Observer) FingerprintInjected(method string, responseFrame []byte) {
	var f jsonrpcFrame
	if json.Unmarshal(responseFrame, &f) != nil || len(f.Result) == 0 {
		return
	}
	o.fingerprint(method, f.Result)
}

// record audits one decidable method. Event names match the in-process audit
// middleware so a chain reads the same whichever side wrote it.
func (o *Observer) record(method string, params json.RawMessage) {
	if o.audit == nil {
		return
	}
	switch method {
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(params, &p)
		o.append("tool.call", map[string]any{
			"tool":        p.Name,
			"args_sha256": digest(p.Arguments),
			"args_len":    len(p.Arguments),
		})
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(params, &p)
		o.append("resource.read", map[string]any{"uri": p.URI})
	case "prompts/get":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(params, &p)
		o.append("prompt.get", map[string]any{
			"prompt":      p.Name,
			"args_sha256": digest(p.Arguments),
		})
	case "completion/complete":
		var p struct {
			Argument struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"argument"`
		}
		_ = json.Unmarshal(params, &p)
		o.append("completion.complete", map[string]any{
			"argument":     clip(p.Argument.Name),
			"value_sha256": digest([]byte(p.Argument.Value)),
			"value_len":    len(p.Argument.Value),
		})
	case "subscriptions/listen":
		o.append("subscriptions.listen", map[string]any{})
	case "server/discover":
		o.append("server.discover", map[string]any{})
	}
}

// fingerprint pins or rechecks a manifest surface from a result frame. Only
// complete single-page responses are fingerprinted: a paginated list would
// otherwise read as drift. With the default page size the manifest is one page.
func (o *Observer) fingerprint(method string, result json.RawMessage) {
	if o.rp == nil {
		return
	}
	switch method {
	case "tools/list", "listTools":
		var r struct {
			Tools      []*mcp.Tool `json:"tools"`
			NextCursor string      `json:"nextCursor"`
		}
		if json.Unmarshal(result, &r) != nil || r.NextCursor != "" {
			return
		}
		o.updateIndex(r.Tools)
		o.pinOrRecheck("tools", func(pinned bool) error {
			if !pinned {
				o.rp.SetBaseline(r.Tools)
				return nil
			}
			return o.rp.RecheckTools(r.Tools, "wire")
		})
	case "prompts/list", "listPrompts":
		var r struct {
			Prompts    []*mcp.Prompt `json:"prompts"`
			NextCursor string        `json:"nextCursor"`
		}
		if json.Unmarshal(result, &r) != nil || r.NextCursor != "" {
			return
		}
		o.pinOrRecheck("prompts", func(pinned bool) error {
			if !pinned {
				o.rp.SetPromptBaseline(r.Prompts)
				return nil
			}
			return o.rp.RecheckPrompts(r.Prompts, "wire")
		})
	case "resources/list", "listResources":
		var r struct {
			Resources  []*mcp.Resource `json:"resources"`
			NextCursor string          `json:"nextCursor"`
		}
		if json.Unmarshal(result, &r) != nil || r.NextCursor != "" {
			return
		}
		o.pinOrRecheck("resources", func(pinned bool) error {
			if !pinned {
				o.rp.SetResourceBaseline(r.Resources)
				return nil
			}
			return o.rp.RecheckResources(r.Resources, "wire")
		})
	case "server/discover", "initialize":
		var r struct {
			Capabilities *mcp.ServerCapabilities `json:"capabilities"`
			Instructions string                  `json:"instructions"`
		}
		if json.Unmarshal(result, &r) != nil {
			return
		}
		o.pinOrRecheck("discover", func(pinned bool) error {
			if !pinned {
				o.rp.SetDiscoverBaseline(r.Capabilities, r.Instructions)
				return nil
			}
			return o.rp.RecheckDiscover(r.Capabilities, r.Instructions, "wire")
		})
	}
}

func (o *Observer) pinOrRecheck(surface string, fn func(pinned bool) error) {
	o.mu.Lock()
	if o.seenSurfaces == nil {
		o.seenSurfaces = map[string]bool{}
	}
	pinned := o.seenSurfaces[surface]
	o.seenSurfaces[surface] = true
	o.mu.Unlock()
	if err := fn(pinned); err != nil {
		// A drift is already audited and (once armed) tripped inside the
		// detector; here it is also surfaced to the operator log.
		o.logger.Warn("rug-pull drift detected on the wire", "surface", surface, "err", err)
	}
}

// ToolFacts returns the tool index built from the observed manifest, for the
// policy engine. It implements policy.ToolIndex.
func (o *Observer) Lookup(tool string) (policy.ToolFacts, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	f, ok := o.index[tool]
	return f, ok
}

func (o *Observer) updateIndex(tools []*mcp.Tool) {
	idx := make(map[string]policy.ToolFacts, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		facts := policy.ToolFacts{Name: t.Name}
		if a := t.Annotations; a != nil {
			facts.ReadOnly = a.ReadOnlyHint
			facts.OpenWorld = a.OpenWorldHint != nil && *a.OpenWorldHint
			facts.Destructive = a.DestructiveHint != nil && *a.DestructiveHint
		}
		idx[t.Name] = facts
	}
	o.mu.Lock()
	o.index = idx
	o.mu.Unlock()
}

func (o *Observer) append(event string, payload map[string]any) {
	if o.audit == nil {
		return
	}
	_, _ = o.audit.Append(event, payload)
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func clip(s string) string {
	if len(s) > maxRecordedString {
		return s[:maxRecordedString]
	}
	return s
}
