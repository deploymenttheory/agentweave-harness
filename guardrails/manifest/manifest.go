// Package manifest implements the session manifest — a bounded, expiring
// grant for one governed session — and the narrow-only composition of the
// policy layers (managed → user → manifest). Semantics are ratified in
// docs/policy-config.md; this package is held to that document.
//
// The package is platform-agnostic and, like policy, has no MCP dependency:
// the decision about a name or a clock is testable with no transport. It
// imports wire only for the typed refusal-code vocabulary, which is
// stdlib-only by construction.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/agentweave-harness/guardrails/hostmatch"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// SchemaVersion is the manifest schema this package reads. Like the policy
// document, an unknown version is refused rather than best-effort parsed.
const SchemaVersion = 1

// Sentinel errors.
var (
	ErrManifestVersion = errors.New("unsupported manifest version")
	ErrNoExpiry        = errors.New(
		"manifest has no expires_after: a manifest exists to bound a session, one with no expiry is not bounded",
	)
	ErrInvalidManifest = errors.New("invalid session manifest")
)

// Manifest is a bounded, expiring grant for one session. Every field narrows:
// a manifest cannot name a tool into existence, raise a limit, or turn
// enforcement off.
type Manifest struct {
	Version int   `json:"version"`
	Allow   Allow `json:"allow"`
	// ExpiresAfter bounds the session's total lifetime, measured from session
	// start. Required: see ErrNoExpiry.
	ExpiresAfter policy.Duration `json:"expires_after"`
	// IdleTimeout, when set, drains the session after that long with no
	// allowed decidable request. Refused requests do not refresh the clock —
	// a denied call must not keep a session alive.
	IdleTimeout policy.Duration `json:"idle_timeout,omitempty"`
}

// Allow is the manifest's grant. For every list, absence and emptiness are
// different statements: an absent list does not restrict its category, an
// explicitly empty list grants nothing in it.
type Allow struct {
	// Tools names the tools the session may call.
	Tools policy.StringSet `json:"tools,omitempty"`
	// Resources bounds what the session may read and launch.
	Resources Resources `json:"resources,omitempty"`
}

// Resources bounds the session's reach into the host and the network.
type Resources struct {
	// Apps names the applications the session may launch. Enforced at the
	// argument level (the App tool's name); carried in the schema from the
	// start so manifests do not change shape when that lands.
	Apps policy.StringSet `json:"apps,omitempty"`
	// Files lists path prefixes a resource read may fall under.
	Files []string `json:"files,omitempty"`
	// Origins lists hosts (exact or "*.example.com") a resource read may
	// target. Origins also feed the composed egress allow-list, so a bounded
	// session's network reach shrinks to match what it may read.
	Origins []string `json:"origins,omitempty"`
}

// utf8BOM mirrors policy.Parse: editors on Windows prepend it and the JSON
// decoder rejects it.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Parse decodes and validates a manifest document. Unknown fields are
// refused — a typo'd grant key silently granting nothing (or everything) is
// the failure being prevented.
func Parse(b []byte) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(b, utf8BOM)))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	if m.Version != SchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrManifestVersion, m.Version, SchemaVersion)
	}
	if m.ExpiresAfter <= 0 {
		return nil, ErrNoExpiry
	}
	if m.IdleTimeout < 0 {
		return nil, fmt.Errorf("%w: negative idle_timeout", ErrInvalidManifest)
	}
	// Origins are compiled at parse time so a malformed pattern fails the
	// load, not the first read it should have bounded.
	if m.Allow.Resources.Origins != nil {
		if _, err := hostmatch.Compile(m.Allow.Resources.Origins); err != nil {
			return nil, fmt.Errorf("%w: origins: %w", ErrInvalidManifest, err)
		}
	}
	return &m, nil
}

// Load reads and parses a manifest file. A named manifest that cannot be
// loaded is a hard error, never "no manifest": silently running wider than
// the grant intended is the failure being prevented.
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied manifest path, by design
	if err != nil {
		return nil, fmt.Errorf("read session manifest: %w", err)
	}
	return Parse(b)
}

// AllowsTool reports whether the manifest grants the tool. A nil Tools list
// does not restrict; an empty one grants nothing.
func (m *Manifest) AllowsTool(name string) bool {
	if m.Allow.Tools == nil {
		return true
	}
	return m.Allow.Tools.Contains(name)
}

// AllowsApp reports whether the manifest grants launching the application. A
// nil Apps list does not restrict; an empty one grants nothing.
func (m *Manifest) AllowsApp(name string) bool {
	if m.Allow.Resources.Apps == nil {
		return true
	}
	return m.Allow.Resources.Apps.Contains(name)
}

// AllowsResource reports whether a resource URI (or path) falls inside the
// manifest's grant: under any files prefix, or targeting any allowed origin.
// With neither list present the manifest does not restrict resources.
func (m *Manifest) AllowsResource(uri string) bool {
	files, origins := m.Allow.Resources.Files, m.Allow.Resources.Origins
	if files == nil && origins == nil {
		return true
	}
	for _, prefix := range files {
		if hasPathPrefix(uri, prefix) {
			return true
		}
	}
	if origins != nil {
		if host := uriHost(uri); host != "" {
			set, err := hostmatch.Compile(origins)
			if err == nil && set.Match(host) {
				return true
			}
		}
	}
	return false
}

// hasPathPrefix reports whether the URI falls under the path prefix,
// comparing case-insensitively with / and \ unified — resource URIs and
// manifest entries routinely disagree on both, and a grant that silently
// misses because of a separator would read as a refusal bug.
func hasPathPrefix(uri, prefix string) bool {
	if prefix == "" {
		return false
	}
	norm := func(s string) string {
		s = strings.ToLower(strings.ReplaceAll(s, `\`, "/"))
		s = strings.TrimPrefix(s, "file:///")
		s = strings.TrimPrefix(s, "file://")
		return strings.TrimSuffix(s, "/")
	}
	u, p := norm(uri), norm(prefix)
	return u == p || strings.HasPrefix(u, p+"/")
}

// uriHost extracts the host from a URI-shaped string without touching the
// network. It requires an explicit scheme://, so a bare path is never read as
// a hostname.
func uriHost(uri string) string {
	i := strings.Index(uri, "://")
	if i < 0 {
		return ""
	}
	rest := uri[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	// Strip userinfo and port.
	if j := strings.LastIndex(rest, "@"); j >= 0 {
		rest = rest[j+1:]
	}
	if j := strings.LastIndex(rest, ":"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
