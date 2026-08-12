// Package harness orchestrates one governed session: it hosts the control
// channel, spawns the governed server as a child with the bootstrap
// environment, pumps the MCP stdio streams through the proxy, records and
// fingerprints the conversation through the observer, and supervises the
// pieces until the session ends.
//
// Current scope: the harness observes and, when given a policy, enforces. It
// proxies byte-faithfully; records the decidable methods into a hash-chained
// audit log and fingerprints the advertised manifest for rug-pull drift (via
// internal/observe); and, when a policy document is configured, decides each
// decidable request against a policy engine whose signals come from the servant
// over the control channel, refusing a denied request on the wire so the server
// never sees it (via internal/enforce). An enforcing policy begins the session
// fail-closed until the engine is ready. It accepts a servant connection if the
// child dials one, and tolerates a child that never dials at all, because a
// proxy that cannot wrap today's shipped server would never be adopted. The
// hello.ack tells the servant which mode governs the session — `enforce` only
// when the policy decider is actually installed, never from the policy document
// alone — which is what licenses a governed server to shed its now-redundant
// in-process enforcement on that signal.
package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/watch"
	"github.com/deploymenttheory/agentweave-harness/internal/control"
	"github.com/deploymenttheory/agentweave-harness/internal/enforce"
	"github.com/deploymenttheory/agentweave-harness/internal/observe"
	"github.com/deploymenttheory/agentweave-harness/internal/proxy"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// Config for one session.
type Config struct {
	// Argv is the governed server's command line, argv[0] the binary.
	Argv []string
	// Logger receives harness diagnostics (stderr only — stdout is the
	// proxied MCP stream).
	Logger *slog.Logger

	// ClientIn/ClientOut are the MCP client streams; nil means the process's
	// own stdin/stdout.
	ClientIn  io.Reader
	ClientOut io.Writer

	// PolicyConfig is the path to the device-policy document the harness
	// enforces. Empty means the harness only observes (records and fingerprints
	// but refuses nothing). A document in audit mode records intended verdicts
	// without refusing; a document in enforce mode refuses on the wire.
	PolicyConfig string
	// AuditSink is where the harness audit chain is written: "" or "stderr"
	// for the stderr stream (AUDIT {json} lines), a directory for a sealed
	// per-session file, or a plain path for an appended JSONL file.
	AuditSink string
	// SessionStamp identifies this session in the audit chain and control
	// channel. Empty lets the caller default it.
	SessionStamp string
	// DriftInterval is how often the harness re-lists the manifest out of band
	// to catch a rug pull between client re-lists. Zero disables it.
	DriftInterval time.Duration
}

// ErrNoArgv reports a Run with no server command line.
var ErrNoArgv = errors.New("harness: no server command given")

// Run executes one governed session and returns when it ends. The child's
// stderr passes through to the harness's stderr: the server's own
// diagnostics and AUDIT lines remain visible to the operator unchanged.
func Run(ctx context.Context, cfg Config) error {
	if len(cfg.Argv) == 0 {
		return ErrNoArgv
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	clientIn := cfg.ClientIn
	if clientIn == nil {
		clientIn = os.Stdin
	}
	clientOut := cfg.ClientOut
	if clientOut == nil {
		clientOut = os.Stdout
	}

	host, err := control.NewHost(logger)
	if err != nil {
		return err
	}
	defer func() { _ = host.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// #nosec G204 -- the operator names the governed server binary by design;
	// that is what the run command is for.
	child := exec.CommandContext(ctx, cfg.Argv[0], cfg.Argv[1:]...)
	child.Stderr = os.Stderr
	child.Env = append(os.Environ(),
		control.EnvPipe+"="+host.Addr,
		control.EnvToken+"="+host.Token,
	)
	serverIn, err := child.StdinPipe()
	if err != nil {
		return fmt.Errorf("harness: server stdin: %w", err)
	}
	serverOut, err := child.StdoutPipe()
	if err != nil {
		return fmt.Errorf("harness: server stdout: %w", err)
	}
	if err := child.Start(); err != nil {
		return fmt.Errorf("harness: start server: %w", err)
	}
	logger.Info("harness: governed server started",
		"pid", child.Process.Pid, "argv0", cfg.Argv[0])

	// The policy the harness enforces is loaded before the pump starts, so its
	// mode is known: an enforcing document means the session begins fail-closed
	// (decidable calls refused until the engine is ready) rather than leaving an
	// unadjudicated window before the servant connects.
	policyDoc, err := loadHarnessPolicy(cfg.PolicyConfig)
	if err != nil {
		return err
	}

	// The observer records the proxied conversation into a hash-chained audit
	// log and fingerprints the advertised manifest for rug-pull drift, and its
	// tool index feeds the policy engine.
	stamp := cfg.SessionStamp
	if stamp == "" {
		stamp = "harness"
	}
	auditDest, err := audit.OpenDestination(cfg.AuditSink, stamp)
	if err != nil {
		return fmt.Errorf("harness: audit destination: %w", err)
	}
	auditLog := audit.NewAuditLog(auditDest)
	defer func() { _ = auditLog.Close() }()
	rp := watch.NewRugPull(func(reason string) {
		logger.Warn("rug-pull drift observed (report-only)", "reason", reason)
	}, auditLog)
	obs := observe.New(auditLog, rp, logger)

	_, _ = auditLog.Append("harness.session.started", map[string]any{"argv0": cfg.Argv[0]})

	p := proxy.New(clientIn, clientOut, serverIn, serverOut, obs)
	// Fail closed while enforcement initializes: an enforcing policy must not
	// leave decidable calls unadjudicated in the window before the servant has
	// connected and its signals are reachable. Non-decidable traffic
	// (initialize, tools/list) is unaffected, so the handshake still proceeds.
	if policyDoc != nil && policyDoc.Mode == policy.ModeEnforcing {
		p.SetInterceptor(enforce.NewInterceptor(
			enforce.DenyAll{Reason: "policy engine initializing"}, logger))
	}

	// Servant acceptance runs concurrently with the session: a Phase-3+ server
	// dials during startup; an older server never does. Once it connects, the
	// harness completes the handshake, builds the policy engine over the
	// observer's tool index and the servant's signals, and swaps the fail-closed
	// interceptor for the real decider. Token mismatch is the one outcome that
	// must end the session — an unauthenticated peer means the bootstrap secret
	// leaked.
	servantFatal := make(chan error, 1)
	go func() {
		sess, aerr := host.AwaitServant(ctx)
		if aerr != nil {
			if errors.Is(aerr, control.ErrBadToken) {
				servantFatal <- aerr
				return
			}
			if !errors.Is(aerr, context.Canceled) {
				logger.Info("harness: no servant connected; proxying observe-only", "reason", aerr)
			}
			return
		}
		defer func() { _ = sess.Close() }()
		logger.Info("harness: servant connected",
			"session", sess.Hello.SessionStamp,
			"proto", sess.Version,
			"signals", len(sess.Hello.Capabilities.Signals),
			"elevated", sess.Hello.Capabilities.Elevated)
		// Build enforcement before the ack, now that the signal source (the
		// servant) is reachable. The ack's mode must be honest: `enforce` is
		// what licenses the server to shed its own in-process enforcement, so
		// it is sent only when the real decider actually got installed —
		// deriving it from the policy document alone would, on a validation
		// failure, leave the harness observe-only *and* the server shed, the
		// one unguarded combination. The servant blocks reading the ack, so
		// nothing races this ordering; Serve (which answers the engine's
		// signal round-trips) starts right after.
		activated := installEnforcement(p, sess, policyDoc, obs, auditLog, logger)
		ackMode := wire.ModeObserve
		if activated && policyDoc.Mode == policy.ModeEnforcing {
			ackMode = wire.ModeEnforce
		}
		_, _ = auditLog.Append("harness.mode.acked", map[string]any{"mode": ackMode})
		if err := sess.Ack(wire.HelloAck{Mode: ackMode}); err != nil {
			logger.Error("harness: hello.ack failed", "err", err)
			return
		}
		if err := sess.Serve(logger, servantHandlers(logger)); err != nil {
			logger.Error("harness: control channel failed", "err", err)
		}
	}()

	if cfg.DriftInterval > 0 {
		go driftMonitor(ctx, p, obs, logger, cfg.DriftInterval)
	}
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- p.Run(ctx) }()

	select {
	case err := <-servantFatal:
		cancel() // kills the child via CommandContext
		_ = child.Wait()
		return fmt.Errorf("harness: killing child: %w", err)
	case err := <-pumpDone:
		// Client EOF: close the server's stdin so it shuts down cleanly,
		// then reap it. Server exit: the pump sees EOF the same way.
		_ = serverIn.Close()
		werr := child.Wait()
		if err != nil {
			return err
		}
		if werr != nil {
			return fmt.Errorf("harness: server exited: %w", werr)
		}
		return nil
	}
}

// driftMonitor re-lists the manifest surfaces out of band on an interval,
// feeding each response through the observer's fingerprint path. Injected
// requests and their responses never reach the client (proxy.Inject consumes
// them), so this is invisible to the session it is watching. Errors are
// expected before the client has initialized the server and are ignored.
func driftMonitor(
	ctx context.Context,
	p *proxy.Proxy,
	obs *observe.Observer,
	logger *slog.Logger,
	interval time.Duration,
) {
	surfaces := []string{"tools/list", "prompts/list", "resources/list"}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, method := range surfaces {
				resp, err := p.Inject(ctx, map[string]any{"jsonrpc": "2.0", "method": method})
				if err != nil {
					logger.Debug("harness: drift re-list failed", "method", method, "err", err)
					continue
				}
				obs.FingerprintInjected(method, resp)
			}
		}
	}
}

// servantHandlers is the Phase-2 control vocabulary: everything is accepted
// and logged, nothing is acted on yet. The handlers grow with the phases.
func servantHandlers(logger *slog.Logger) map[string]control.Handler {
	logged := func(env wire.Envelope) error {
		logger.Debug("harness: control message", "type", env.Type)
		return nil
	}
	return map[string]control.Handler{
		wire.TypeHeartbeat:       logged,
		wire.TypePosturePush:     logged,
		wire.TypeSignalResult:    logged,
		wire.TypeCredentialEvent: logged,
		wire.TypeEgressState:     logged,
		wire.TypeActuateResult:   logged,
		wire.TypeAuditAnchor:     logged,
		wire.TypePlanEvaluate:    logged,
	}
}
