// Nudges the local Pulse service when the node's role changes.
//
// Pulse is purely event-driven (no timer sweeps), and a schedule-only rule may get no events at all after a
// switchover, so without this nudge it would not start until the daemon restarts. Best effort by design: an
// HA operation must not depend on a neighbouring service.
package agentd

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"strings"
	"time"
)

// PulseControlSocket is the same on every install, so it is not in the HA config (which holds only per-node values).
const PulseControlSocket = "/run/dns-panel/pulse/control.sock"

// Timeouts reuse the daemon's existing scales: one attempt = cmdTimeout, total = shellTimeout.
// Retries matter because promotion happens once: a resumed operation is answered from the journal
// (Done[key]) and never reaches the executor again. If Pulse is not running, it sets itself up on start.
var (
	pulseNotifyTimeout = cmdTimeout
	pulseRetryWindow   = shellTimeout
)

// pulseRetryFirst is the first backoff, equal to one attempt's timeout; it then doubles up to the window.
func pulseRetryFirst() time.Duration { return pulseNotifyTimeout }

// notifyPulse tells Pulse the role changed; the command carries no data, Pulse decides what to do.
//
// It is sent on both promotion and demotion: on demotion Pulse must drop pending "for N s" holds, or a hold
// started before demotion keeps counting on STANDBY and later reports a false continuous N seconds.
// Retries run in the background and never block the operation.
func notifyPulse(path, cmd string) {
	go func() {
		var spent time.Duration
		for attempt := 1; ; attempt++ {
			err := sendPulseCmd(path, cmd)
			if err == nil {
				return
			}
			// No socket: Pulse is not running or not installed. No retries and no log noise.
			if errors.Is(err, fs.ErrNotExist) {
				return
			}
			back := pulseRetryFirst() << (attempt - 1)
			if spent+back > pulseRetryWindow {
				log.Printf("pulse: %s not delivered after %d attempts: %v", cmd, attempt, err)
				return
			}
			time.Sleep(back)
			spent += back
		}
	}()
}

// sendPulseCmd makes one attempt. Pulse answers ok only after it has done the work, not on receipt.
func sendPulseCmd(path, cmd string) error {
	conn, err := net.DialTimeout("unix", path, pulseNotifyTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(pulseNotifyTimeout))
	if _, err := conn.Write([]byte(`{"cmd":"` + cmd + `"}` + "\n")); err != nil {
		return err
	}
	// Read the answer: a partial result (schedules set, evaluation still retrying) is not delivery.
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("no answer: %w", err)
	}
	if !strings.Contains(line, `"ok":true`) {
		// Pulse retries the evaluation itself, but we still retry: promotion happens only once.
		return fmt.Errorf("accepted only in part: %s", strings.TrimSpace(line))
	}
	return nil
}

// pulseRoleChanged runs after a successful role change, including a noop: the node may have reached that
// state earlier without Pulse knowing.
func pulseRoleChanged(r Response, err error, cmd string) {
	if err != nil || !r.OK {
		return
	}
	notifyPulse(PulseControlSocket, cmd)
}
