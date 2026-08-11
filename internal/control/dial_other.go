//go:build !windows

package control

import (
	"fmt"
	"net"
)

// Dial connects to the control channel — see dial_windows.go for why the
// dialer lives here.
func Dial(addr string) (net.Conn, error) {
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("control: dial %s: %w", addr, err)
	}
	return conn, nil
}
