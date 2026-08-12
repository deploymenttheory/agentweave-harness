package harness

// egresswire relocates the device egress proxy into the harness for governed
// sessions: the composed policy (already narrowed by the session manifest's
// origins) owns the allowlist, the proxy runs in this process where the
// contained server cannot reach its configuration, and the bound port is
// announced to the servant in the hello.ack so OS enforcement on the host can
// point at it. Standalone servers keep their in-process proxy; this file only
// runs under `agentweave-harness run`.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/deploymenttheory/agentweave-harness/guardrails/egress"
	"github.com/deploymenttheory/agentweave-harness/guardrails/hostmatch"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// startEgressProxy starts the harness-side loopback proxy when the composed
// policy enables egress. It returns the running service (nil when egress is
// off) and the bound port for the hello.ack.
//
// A composed allowlist that admits nothing — an empty intersection of layers
// that disagree completely — refuses to start rather than presenting a proxy
// that refuses every request: that reads as a broken network, not a policy,
// and the operator should learn the layers are incompatible at startup, not
// from a session that cannot reach anything.
func startEgressProxy(
	ctx context.Context,
	layers *sessionLayers,
	logger *slog.Logger,
) (*egress.Service, int, error) {
	if layers.composed == nil || !layers.composed.Config.Egress.Enabled {
		return nil, 0, nil
	}
	e := layers.composed.Config.Egress
	listen := e.Listen
	if listen == "" {
		listen = policy.DefaultEgressListen
	}
	allow, err := hostmatch.Compile(e.Allow)
	if err != nil {
		return nil, 0, fmt.Errorf("harness: egress allowlist: %w", err)
	}
	ports := e.AllowPorts
	if len(ports) == 0 {
		ports = policy.DefaultEgressPorts()
	}
	// The token names an environment variable, never a value: the policy
	// document stays reviewable, the same rule as every other secret.
	token := ""
	if e.AuthTokenEnv != "" {
		token = os.Getenv(e.AuthTokenEnv)
	}
	svc, err := egress.Start(ctx, egress.Config{
		Listen:       listen,
		Allow:        allow,
		AllowPorts:   ports,
		AllowPrivate: e.AllowPrivateNetworks,
		AuthToken:    token,
		Enforcement:  e.Enforcement(),
		Logger:       logger,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("harness: egress proxy: %w", err)
	}
	port, err := proxyPort(svc.Addr())
	if err != nil {
		svc.Stop()
		return nil, 0, err
	}
	return svc, port, nil
}

// proxyPort extracts the bound port for the ack.
func proxyPort(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("harness: egress proxy address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return 0, fmt.Errorf("harness: egress proxy port %q: %w", p, err)
	}
	return port, nil
}

// effectiveConfig assembles the hello.ack's effective config from the
// composed posture: the settings the wire contract says the server must apply
// before building its tool surface. ProtectedPaths stay empty — the harness
// has no knowledge of host paths; the server derives its own from its local
// config and the ack can only add to them.
func effectiveConfig(layers *sessionLayers, egressPort int) wire.EffectiveConfig {
	ec := wire.EffectiveConfig{EgressProxyPort: egressPort}
	if egressPort != 0 {
		// The firewall allow rule under a global outbound block must name the
		// process actually dialing out — this one, now that the proxy runs
		// harness-side. Best effort: an empty path degrades to the server
		// falling back to its own executable, which the server-side spec
		// treats as the standalone case.
		if exe, err := os.Executable(); err == nil {
			ec.EgressProxyExecutable = exe
		}
	}
	if layers.composed != nil {
		ec.EnforceHTTPS = layers.composed.Config.EnforceHTTPS
		ec.Banner = layers.composed.Config.Transparency.Banner
	}
	return ec
}

// requireServableEgress is the elevation gate at the handshake: a composed
// policy naming applications or block_all_outbound needs OS actuation on the
// host, which needs elevation the servant either has or does not. Serving the
// session anyway would silently deliver a weaker posture than the documents
// describe — the failure being prevented — so a non-elevated servant refuses
// the session outright.
func requireServableEgress(layers *sessionLayers, caps wire.Capabilities) error {
	if layers.composed == nil {
		return nil
	}
	e := layers.composed.Config.Egress
	if !e.Enabled {
		return nil
	}
	needsElevation := len(e.Applications) > 0 || e.BlockAllOutbound
	if needsElevation && !caps.Elevated {
		return fmt.Errorf("%w: the composed egress policy names %s", ErrEgressNeedsElevation, egressTierName(e))
	}
	return nil
}

// ErrEgressNeedsElevation reports a composed egress posture the connected
// servant cannot apply: OS enforcement (scoped or global) needs elevation the
// servant did not advertise, and serving the session anyway would silently
// deliver a weaker posture than the documents describe.
var ErrEgressNeedsElevation = errors.New(
	"harness: egress posture needs OS enforcement this servant cannot apply without elevation")

func egressTierName(e policy.EgressPolicy) string {
	if e.BlockAllOutbound {
		return "block_all_outbound"
	}
	return "applications"
}
