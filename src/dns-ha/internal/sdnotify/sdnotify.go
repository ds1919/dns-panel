// Package sdnotify implements the systemd sd_notify protocol for Type=notify units.
//
// Readiness is reported as an event: systemctl start/restart returns exactly when the daemon sends
// READY=1, so nothing waiting on it has to guess timing.
package sdnotify

import (
	"net"
	"os"
)

// Notify sends state (e.g. "READY=1"). Outside systemd there is no NOTIFY_SOCKET and nobody to tell, so it returns nil.
func Notify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	// The socket is for this daemon only: children inheriting it make systemd log
	// "reception only permitted for main PID".
	os.Unsetenv("NOTIFY_SOCKET")
	if addr[0] == '@' {
		addr = "\x00" + addr[1:] // abstract namespace
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
