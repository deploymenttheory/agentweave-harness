// Package harness orchestrates one governed session: it hosts the control
// channel, spawns the governed server as a child with the bootstrap
// environment, pumps the MCP stdio streams through the proxy, and supervises
// the pieces until the session ends.
//
// Phase 2 scope: the harness is a transparent observer. It proxies
// byte-faithfully, accepts a servant connection if the child dials one (a
// Phase-3 server), acks it in observe mode, and tolerates a child that never
// dials at all (a pre-Phase-3 server) — logging that fact rather than
// failing, because a proxy that cannot wrap today's shipped server would
// never be adopted. Enforcement arrives with Phase 4.
package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"

	"github.com/deploymenttheory/agentweave-harness/internal/control"
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

	// Servant acceptance runs concurrently with the session: a Phase-3+
	// server dials during startup; an older server never does. Token
	// mismatch is the one outcome that must end the session — an
	// unauthenticated peer means the bootstrap secret leaked.
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
		if err := sess.Ack(wire.HelloAck{Mode: wire.ModeObserve}); err != nil {
			logger.Error("harness: hello.ack failed", "err", err)
			return
		}
		if err := sess.Serve(logger, servantHandlers(logger)); err != nil {
			logger.Error("harness: control channel failed", "err", err)
		}
	}()

	p := proxy.New(clientIn, clientOut, serverIn, serverOut, logObserver{logger})
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

// logObserver is the Phase-2 stand-in for the audit/rug-pull observer: it
// counts frames at debug level and never touches them.
type logObserver struct{ logger *slog.Logger }

func (o logObserver) OnClientFrame(raw []byte) {
	o.logger.Debug("harness: client frame", "bytes", len(raw))
}

func (o logObserver) OnServerFrame(raw []byte) {
	o.logger.Debug("harness: server frame", "bytes", len(raw))
}
