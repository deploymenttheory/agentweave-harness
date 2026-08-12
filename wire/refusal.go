package wire

// Typed refusal codes, the machine-readable half of a refusal. They live in
// this package so both enforcement stacks — the harness's wire-level
// interceptor and the in-process middleware — import one vocabulary, and so a
// governed server or client can match on the code without parsing prose.
//
// The codes name the manifest and session-lifetime refusals, which have no
// failing signal to explain them. Policy-rule denials keep their reason text
// (the signal and rule that failed) and carry no code.
const (
	// RefusalPermissionDenied: the session manifest's allow.tools does not
	// include the tool being called.
	RefusalPermissionDenied = "permission_denied"
	// RefusalBoundedResourceOutsideManifest: the resource being read falls
	// outside the manifest's allow.resources grant.
	RefusalBoundedResourceOutsideManifest = "bounded_resource_outside_manifest"
	// RefusalSessionExpired: the manifest's expires_after has elapsed; the
	// session drains, refusing decidable requests without being killed.
	RefusalSessionExpired = "session_expired"
	// RefusalSessionIdleTimeout: the manifest's idle_timeout elapsed with no
	// allowed decidable request. Refused requests do not refresh the idle
	// clock — a denied call must not keep a session alive.
	RefusalSessionIdleTimeout = "session_idle_timeout"
)

// Refusal is the structured payload a typed refusal carries in a JSON-RPC
// error's data member. tools/call has no data member; there the code rides in
// the IsError result text.
type Refusal struct {
	Code string `json:"code"`
}
