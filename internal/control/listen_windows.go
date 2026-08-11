//go:build windows

package control

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// listen creates the named pipe with an SDDL admitting only SYSTEM and the
// current user. The pipe name carries 16 random bytes so a concurrent
// session (or a squatter guessing names) cannot collide with it; the SDDL,
// not the name, is the access control.
func listen() (net.Listener, string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, "", fmt.Errorf("control: pipe name: %w", err)
	}
	name := `\\.\pipe\agentweave-` + hex.EncodeToString(buf[:])

	sid, err := currentUserSID()
	if err != nil {
		return nil, "", err
	}
	// Protected DACL: full access for SYSTEM and the session user, nothing
	// else — the same posture as the credentials-file ACL check on the
	// server side.
	sddl := fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;%s)", sid)

	ln, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		return nil, "", fmt.Errorf("control: listen %s: %w", name, err)
	}
	return ln, name, nil
}

func currentUserSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("control: token user: %w", err)
	}
	return user.User.Sid.String(), nil
}
