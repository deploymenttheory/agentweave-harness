//go:build !windows

package control

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// listen creates a unix socket in a fresh mode-0700 directory — the
// non-Windows analogue of the named pipe's SDDL, and the transport CI's
// ubuntu leg exercises. The directory permission is the access control; the
// socket file inherits protection from it.
func listen() (net.Listener, string, error) {
	dir, err := os.MkdirTemp("", "agentweave-*")
	if err != nil {
		return nil, "", fmt.Errorf("control: socket dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("control: socket dir mode: %w", err)
	}
	path := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, "", fmt.Errorf("control: listen %s: %w", path, err)
	}
	return ln, path, nil
}
