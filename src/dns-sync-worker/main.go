// dns-sync-worker is the panel's background scheduler. It decides only WHEN to run a job; what a job does
// (retry a zone, reconcile policy, probe the old server, watch catalogs) and the HA write gate stay in the
// panel's Perl code, run as coarse passes of libexec/sync-task.pl.
//
// All state is durable in the database (next_retry_at, the probe queue, the policy itself): every pass
// reports the schedule it leaves behind, and the daemon sleeps until the nearest deadline. The panel wakes
// it through a datagram socket when it queues something; a lost wake costs at most one catalog interval.
//
//	dns-sync-worker [-task /opt/dns-panel/libexec/sync-task.pl] [-socket /run/dns-panel/sync/wake.sock]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var revision = "dev"

// scheduleRetry is the daemon's own pause between schedule reads while no pass can report at all (the
// panel's code or database is broken); it is not a panel setting because no setting can be read then.
const scheduleRetry = 10 * time.Second

// report is the last JSON line of a sync-task pass.
type report struct {
	Gate           string `json:"gate"`
	OK             int    `json:"ok"`
	NextRetryIn    *int   `json:"next_retry_in"`
	ProbeQueued    int    `json:"probe_queued"`
	CatalogEvery   int    `json:"catalog_every"`
	ReconcileEvery int    `json:"reconcile_every"`
	RetryFailedIn  int    `json:"retry_failed_in"`
	Progress       *int   `json:"progress"`
	Summary        string `json:"summary"`
}

// lane is one kind of pass with its own deadline. stalled holds a lane that made no progress (a busy zone,
// an unreachable old server) until the next catalog interval or a wake, so it cannot spin.
type lane struct {
	task    string
	at      time.Time // zero = nothing to do
	stalled time.Time
	failing bool // last pass failed; logged once per streak
}

type worker struct {
	task, sock     string
	taskTimeout    time.Duration
	catalogEvery   time.Duration
	reconcileEvery time.Duration
	retryFailed    time.Duration // a failed reconcile runs again after this, not after a full interval
	gate           string
	retry, probe   lane
	catalogs       lane
	reconcile      lane
	schedule       lane // never scheduled itself; tracks failures of plain schedule reads
}

func main() {
	w := &worker{}
	flag.StringVar(&w.task, "task", filepath.Join(exeDir(), "..", "libexec", "sync-task.pl"), "the Perl pass runner")
	flag.StringVar(&w.sock, "socket", "/run/dns-panel/sync/wake.sock", "wake socket (datagrams from the panel)")
	flag.DurationVar(&w.taskTimeout, "task-timeout", 10*time.Minute, "a hung pass is killed after this")
	flag.Parse()
	log.SetFlags(0)
	w.retry.task, w.probe.task, w.catalogs.task, w.reconcile.task, w.schedule.task = "retry-due", "probe-batch", "catalogs", "reconcile", "schedule"

	wake, err := listenWake(w.sock)
	if err != nil {
		log.Fatalf("dns-sync-worker: wake socket %s: %v", w.sock, err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("dns-sync-worker %s: started (task %s)", revision, w.task)
	sdNotify("READY=1")

	// The intervals are the panel's settings and arrive with the first report; until one comes, only the
	// schedule read is retried.
	for w.pass(&w.schedule) == nil || w.catalogEvery == 0 {
		t := time.NewTimer(scheduleRetry)
		select {
		case <-t.C:
		case <-wake:
			t.Stop()
		case <-stop:
			log.Print("dns-sync-worker: stopped")
			return
		}
	}
	now := time.Now()
	w.catalogs.at, w.reconcile.at = now, now // a fresh start reconciles everything once
	for {
		if l := w.due(time.Now()); l != nil {
			w.run(l)
			continue
		}
		timer := time.NewTimer(time.Until(w.next()))
		select {
		case <-wake:
			timer.Stop()
			drain(wake)
			w.retry.stalled, w.probe.stalled = time.Time{}, time.Time{}
			w.pass(&w.schedule)
		case <-timer.C:
		case <-stop:
			log.Print("dns-sync-worker: stopped")
			return
		}
	}
}

// due picks the lane to run now, if any. While the node may not write (STANDBY, freeze, unknown HA), only
// the catalog lane runs - as a plain schedule read that notices the gate opening.
func (w *worker) due(now time.Time) *lane {
	if w.gate != "allow" {
		if !w.catalogs.at.After(now) {
			return &w.catalogs
		}
		return nil
	}
	for _, l := range []*lane{&w.retry, &w.catalogs, &w.reconcile, &w.probe} {
		if !l.at.IsZero() && !l.at.After(now) && !l.stalled.After(now) {
			return l
		}
	}
	return nil
}

func (w *worker) next() time.Time {
	next := w.catalogs.at
	if w.gate == "allow" {
		for _, l := range []*lane{&w.retry, &w.reconcile, &w.probe} {
			at := l.at
			if l.stalled.After(at) {
				at = l.stalled
			}
			if !l.at.IsZero() && at.Before(next) {
				next = at
			}
		}
	}
	return next
}

func (w *worker) run(l *lane) {
	// Periodic lanes get their next deadline when the pass ENDS: a pass longer than its interval must not
	// come out overdue and run again back to back, crowding out the rest.
	periodic := l == &w.catalogs || l == &w.reconcile
	if periodic {
		l.at = time.Time{}
	}
	var r *report
	if l == &w.catalogs && w.gate != "allow" {
		r = w.pass(&w.schedule)
	} else {
		r = w.pass(l)
	}
	if periodic && l.at.IsZero() { // the pass may have set it itself: catch-up after the gate opened
		every := w.catalogEvery
		if l == &w.reconcile {
			every = w.reconcileEvery
			if r == nil || r.OK == 0 {
				every = w.retryFailed
			}
		}
		l.at = time.Now().Add(every)
	}
}

// pass runs one sync-task pass and takes the schedule it reports; nil when there was no report.
func (w *worker) pass(l *lane) *report {
	task := l.task
	r, err := w.exec(task)
	now := time.Now()
	// A pass that reported back has logged its own problems, and any backoff lives in the database. Only a
	// pass with no report (crashed, killed, not runnable) is the daemon's to log - once per streak.
	if r == nil {
		if !l.failing {
			log.Printf("dns-sync-worker: %s: %v", task, err)
		}
		l.failing = true
		l.stalled = now.Add(w.catalogEvery)
		return nil
	}
	if l.failing {
		log.Printf("dns-sync-worker: %s: ok again", task)
		l.failing = false
	}
	if r.Summary != "" {
		log.Printf("dns-sync-worker: %s", r.Summary)
	}
	if r.Gate != w.gate {
		if w.gate != "" || r.Gate != "allow" {
			log.Printf("dns-sync-worker: HA gate %s", map[string]string{"allow": "open: node takes writes",
				"skip": "closed: STANDBY or freeze, nothing is written", "fail": "unknown: fail-closed, nothing is written"}[r.Gate])
		}
		if r.Gate == "allow" && w.gate != "" {
			w.reconcile.at, w.catalogs.at = now, now // just became ACTIVE: catch up at once
		}
		w.gate = r.Gate
	}
	if r.CatalogEvery > 0 {
		w.catalogEvery = time.Duration(r.CatalogEvery) * time.Second
	}
	if r.ReconcileEvery > 0 {
		w.reconcileEvery = time.Duration(r.ReconcileEvery) * time.Second
	}
	if r.RetryFailedIn > 0 {
		w.retryFailed = time.Duration(r.RetryFailedIn) * time.Second
	}
	w.retry.at = time.Time{}
	if r.NextRetryIn != nil {
		w.retry.at = now.Add(time.Duration(*r.NextRetryIn) * time.Second)
	}
	w.probe.at = time.Time{}
	if r.ProbeQueued > 0 {
		w.probe.at = now
	}
	// A pass that moved nothing would, rescheduled at once, only repeat itself.
	if r.Progress != nil && *r.Progress == 0 && !l.at.IsZero() && !l.at.After(now) {
		l.stalled = now.Add(w.catalogEvery)
	}
	return r
}

func (w *worker) exec(task string) (*report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), w.taskTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.task, task)
	cmd.Env = append(os.Environ(), "DNS_SYNC_NO_WAKE=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr // the task's own problem lines go straight to the journal
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, errors.New("killed after " + w.taskTimeout.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var r report
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil || r.Gate == "" {
		if runErr != nil {
			return nil, runErr
		}
		return nil, errors.New("no report from the task")
	}
	return &r, nil // exit 1 with a report = a pass with problems it has already logged
}

// listenWake opens the datagram socket the panel pokes. Any datagram means "look at the database again".
func listenWake(path string) (<-chan struct{}, error) {
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
	old := syscall.Umask(0o117)
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	ch := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := c.ReadFromUnix(buf); err != nil {
				log.Fatalf("dns-sync-worker: wake socket: %v", err)
			}
			select {
			case ch <- struct{}{}:
			default: // a wake is already pending; they coalesce
			}
		}
	}()
	return ch, nil
}

func drain(ch <-chan struct{}) {
	select {
	case <-ch:
	default:
	}
}

func exeDir() string {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return "/opt/dns-panel/bin"
	}
	return filepath.Dir(exe)
}

// sdNotify tells systemd (Type=notify) the wake socket is open.
func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	os.Unsetenv("NOTIFY_SOCKET")
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		log.Printf("dns-sync-worker: sd_notify: %v", err)
		return
	}
	c.Write([]byte(state))
	c.Close()
}
