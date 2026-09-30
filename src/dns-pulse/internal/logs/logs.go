// Package logs has exactly three levels:
//
//	debug - handshakes, task assignment, confirms, deadline rescheduling: "why it was decided";
//	info  - startup, connects/disconnects, task set changes, significant transitions;
//	warn  - transient failures: database, HA manager, bad fingerprint, a check that cannot run.
//
// There is deliberately no error level: output goes to journald, and fatal conditions are logged as
// warn and end the process.
package logs

import (
	"log"
	"strings"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
)

var current = Info

func SetLevel(name string) {
	switch strings.ToLower(name) {
	case "debug":
		current = Debug
	case "warn":
		current = Warn
	default:
		current = Info
	}
}

func Debugf(f string, a ...any) {
	if current <= Debug {
		log.Printf("debug: "+f, a...)
	}
}
func Infof(f string, a ...any) {
	if current <= Info {
		log.Printf(f, a...)
	}
}
func Warnf(f string, a ...any) { log.Printf("warn: "+f, a...) }
