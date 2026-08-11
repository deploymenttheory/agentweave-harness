// Command agentweave-harness is the adjudication harness for MCP servers and
// computer-use agents. It will spawn a governed MCP server as a child process,
// proxy the stdio MCP transport between client and server, and own policy,
// audit, rug-pull detection and containment decisions from outside the process
// they govern.
//
// Phase 0 ships only the CLI skeleton and the ratified design documents under
// docs/. The run/check/policy/verify commands land in later phases; see
// docs/architecture.md for the phase plan.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "agentweave-harness",
		Short: "Adjudication harness that wraps MCP servers and computer-use agents",
		Long: "agentweave-harness wraps an MCP server in a separate process: it proxies the\n" +
			"stdio MCP transport, decides every request against policy, keeps the audit\n" +
			"chain, and orders containment — so the governed server is never its own\n" +
			"adjudicator. See docs/architecture.md.",
		SilenceUsage: true,
	}

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the harness version",
		Run: func(cmd *cobra.Command, _ []string) {
			// stdout carries the proxied MCP stream once `run` exists; version is
			// the one command whose output belongs on stdout by convention.
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	})

	if err := root.Execute(); err != nil {
		// Diagnostics go to stderr — stdout is reserved for the proxied MCP
		// transport, the same rule the governed server follows.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
