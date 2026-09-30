package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Commands and responses (ok is 1/0, as the panel has always received it):
//
//	{"cmd":"ping"}                                        → {"ok":1,"pong":1}
//	{"cmd":"rediscover"}                                  → {"ok":1,"output":"..."}
//	{"cmd":"purge","zone":"z"}                            → {"ok":1,"output":"N"}   zone and its subtree
//	{"cmd":"notify","zone":"z"}                           → {"ok":1,"output":"..."}
//	{"cmd":"retrieve","zone":"z"}                         → {"ok":1,"output":"..."} SLAVE: AXFR from primary now
//	{"cmd":"verify","zone":"z","expect_serial":N}         → {"ok":1,"served":true,"serial":N,"matches":true}
//	{"cmd":"soa_at","zone":"z","server":"ip"}             → {"ok":1,"serial":N}     SOA at another server
//	{"cmd":"axfr_at","zone":"z","server":"ip","key":{…}}  → {"ok":1,"records":[…]}  AXFR from another server
func handle(req any, cfg Config) map[string]any {
	r, isObj := req.(map[string]any)
	if !isObj {
		return fail("bad request")
	}
	cmd := text(r["cmd"])
	switch cmd {
	case "ping":
		return map[string]any{"ok": 1, "pong": 1}
	case "rediscover":
		ok, out := control(cfg, "rediscover")
		return map[string]any{"ok": b(ok), "output": out}
	case "purge", "notify", "retrieve":
		z, valid := zone(r["zone"])
		if !valid {
			return fail("invalid zone")
		}
		if cmd == "purge" {
			z += "$" // "zone$" flushes the zone and its whole subtree
		}
		ok, out := control(cfg, cmd, z)
		return map[string]any{"ok": b(ok), "output": out}
	case "verify":
		return verify(r, cfg)
	case "soa_at":
		return soaAt(r, cfg)
	case "axfr_at":
		return axfrAt(r, cfg)
	}
	return fail(fmt.Sprintf("unknown cmd '%s'", cmd))
}

func verify(r map[string]any, cfg Config) map[string]any {
	z, valid := zone(r["zone"])
	if !valid {
		return fail("invalid zone")
	}
	ok, out := run(cfg, cfg.Dig, "+short", "@"+cfg.VerifyResolver, z, "SOA")
	if !ok {
		return fail("dig failed: " + out)
	}
	serial, served := soaSerial(out)
	res := map[string]any{"ok": 1, "served": served, "serial": nil}
	if served {
		res["serial"] = serial
	}
	if exp := text(r["expect_serial"]); digits.MatchString(exp) {
		want, err := strconv.ParseUint(exp, 10, 64)
		res["matches"] = served && err == nil && serial == want
	}
	return res
}

// soaAt answers one question: does our copy have the old master's zone version, or are we behind? Promoting a
// stale copy would replace the live zone with an old one.
func soaAt(r map[string]any, cfg Config) map[string]any {
	z, valid := zone(r["zone"])
	if !valid {
		return fail("invalid zone")
	}
	srv, valid := ip(r["server"])
	if !valid {
		return fail("invalid server address")
	}
	ok, out := run(cfg, cfg.Dig, "+short", "+tries=1", "@"+srv, z, "SOA")
	if !ok {
		return fail("dig failed: " + out)
	}
	serial, served := soaSerial(out)
	if !served {
		return fail("no SOA from " + srv)
	}
	return map[string]any{"ok": 1, "serial": serial}
}

var (
	keyName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	keyAlg  = regexp.MustCompile(`(?i)^hmac-(?:md5|sha1|sha224|sha256|sha384|sha512)$`)
	keyB64  = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	failed  = regexp.MustCompile(`(?i)^;\s*Transfer failed`)
	badSig  = regexp.MustCompile(`(?i)^;;\s*Couldn't verify signature`)
	status  = regexp.MustCompile(`status:\s*([A-Z]+)`)
)

// axfrAt returns the zone's records from another server (migration off the old master: Probe, Diff, Import).
// Lines go back as dig prints them; the panel parses them.
func axfrAt(r map[string]any, cfg Config) map[string]any {
	z, valid := zone(r["zone"])
	if !valid {
		return fail("invalid zone")
	}
	srv, valid := ip(r["server"])
	if !valid {
		return fail("invalid server address")
	}
	args := []string{"+noall", "+answer", "+comments", "+tries=1", "@" + srv, z, "AXFR"}
	var ok bool
	var out string
	if key := r["key"]; truthy(key) {
		k, isObj := key.(map[string]any)
		name, alg, secret := text(k["name"]), text(k["algorithm"]), text(k["secret"])
		if !isObj || !keyName.MatchString(name) || !keyAlg.MatchString(alg) || !keyB64.MatchString(secret) {
			return fail("invalid TSIG key")
		}
		// The key goes via stdin: argv is visible in ps, and AppArmor's dig profile won't read files from /tmp.
		var stderr string
		ok, out, stderr = runErr(cfg, fmt.Sprintf("key \"%s\" { algorithm %s; secret \"%s\"; };\n", name, alg, secret),
			cfg.Dig, append([]string{"-k", "/dev/stdin"}, args...)...)
		// When dig cannot read the key it says so on stderr and does the AXFR UNSIGNED, exit 0.
		if strings.Contains(strings.ToLower(stderr), "key") {
			return fail("dig could not use the TSIG key: " + stderr)
		}
	} else {
		ok, out = run(cfg, cfg.Dig, args...)
	}
	if !ok {
		return fail("dig failed: " + out)
	}
	lines := strings.Split(out, "\n")
	// dig reports a refused transfer as a comment with exit 0; it is not an empty zone. The status tells why:
	// REFUSED — allow-transfer denies us, NOTAUTH — not its zone, SERVFAIL — the zone isn't loaded there.
	for _, l := range lines {
		if !failed.MatchString(l) {
			continue
		}
		st := "?"
		for _, l := range lines {
			if m := status.FindStringSubmatch(l); m != nil {
				st = m[1]
				break
			}
		}
		for _, l := range lines {
			if badSig.MatchString(l) {
				return map[string]any{"ok": 0, "status": st, "tsig_rejected": 1, "error": srv + " rejected the TSIG key (" + st + ")"}
			}
		}
		return map[string]any{"ok": 0, "status": st, "error": srv + " refused the transfer (" + st + ")"}
	}
	records := []string{}
	for _, l := range lines {
		if l != "" && !strings.HasPrefix(l, ";") {
			records = append(records, l)
		}
	}
	return map[string]any{"ok": 1, "records": records}
}

// run executes argv without a shell under the timeout: (ok, stdout). stderr goes to the journal.
func run(cfg Config, name string, args ...string) (bool, string) {
	ok, out, _ := exe(cfg, "", name, args, false, false)
	return ok, out
}

// control runs pdns_control, one at a time: the old agent was sequential, these commands are quick, and
// concurrent rediscover/purge/notify would only add interleavings nobody has reasoned about.
func control(cfg Config, args ...string) (bool, string) {
	ok, out, _ := exe(cfg, "", cfg.PdnsControl, args, false, true)
	return ok, out
}

// pdnsControl is the turn at pdns_control; a request waits for it within its own timeout.
var pdnsControl = make(chan struct{}, 1)

// waitDelay bounds how long a killed child's leftover pipe holders may delay the reply.
const waitDelay = time.Second

// runErr is run with stdin and stderr captured separately: (ok, stdout, stderr).
func runErr(cfg Config, stdin string, name string, args ...string) (bool, string, string) {
	return exe(cfg, stdin, name, args, true, false)
}

func exe(cfg Config, stdin, name string, args []string, captureErr, exclusive bool) (bool, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if exclusive {
		select {
		case pdnsControl <- struct{}{}:
			defer func() { <-pdnsControl }()
		case <-ctx.Done():
			return false, "timeout", ""
		}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = waitDelay
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	if captureErr {
		cmd.Stderr = &errb
	} else {
		cmd.Stderr = os.Stderr
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return false, "timeout", ""
	}
	if err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			return false, err.Error(), ""
		}
	}
	return err == nil, chomp(out.String()), chomp(errb.String())
}

var digits = regexp.MustCompile(`^\d+$`)

// soaSerial takes the serial from "ns hostmaster serial refresh retry expire minimum".
func soaSerial(out string) (uint64, bool) {
	f := strings.Fields(out)
	if len(f) < 3 || !digits.MatchString(f[2]) {
		return 0, false
	}
	n, err := strconv.ParseUint(f[2], 10, 64)
	return n, err == nil
}

// zone validates and normalises a zone name exactly as the panel does (dns_validate_zonename).
func zone(v any) (string, bool) {
	name := strings.TrimSpace(text(v))
	for i := 0; i < len(name); i++ {
		if name[i] > 0x7f {
			return "", false
		}
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || len(name) > 253 {
		return "", false
	}
	for _, l := range strings.Split(name, ".") {
		if len(l) == 0 || len(l) > 63 || !label.MatchString(l) {
			return "", false
		}
	}
	return name, true
}

var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ip accepts a plain IPv4/IPv6 address (what inet_pton takes), returned as given.
func ip(v any) (string, bool) {
	s := text(v)
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return s, true
}

// text is a JSON scalar as a string (numbers keep their literal form); anything else is "".
func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return ""
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != "" && x != "0"
	case json.Number:
		return x.String() != "0"
	}
	return true
}

func fail(msg string) map[string]any { return map[string]any{"ok": 0, "error": msg} }

func b(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func chomp(s string) string { return strings.TrimSuffix(s, "\n") }
