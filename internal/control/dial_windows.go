//go:build windows

package control

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// Dial connects to the control channel. The harness itself never dials —
// servants do — but the handshake tests and in-repo fake servants need the
// client end, and keeping the dialer beside the listener keeps the two
// transports in one place. Governed servers outside this repo implement
// their own dialer against the documented bootstrap contract.
func Dial(addr string) (net.Conn, error) {
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(addr, &timeout)
	if err != nil {
		return nil, fmt.Errorf("control: dial %s: %w", addr, err)
	}
	return conn, nil
}
