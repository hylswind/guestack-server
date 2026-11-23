// Package safelog is the only logging API of guestackd.
//
// It can emit only a closed set of event names and integer counters, all
// defined in this file. Nothing else can be printed through it: there is no
// format string, no error value, no free text. This is what keeps phone
// numbers, tokens and S out of the logs (spec/registration.md, "Privacy").
package safelog

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event is a log event. Values exist only as the variables below.
type Event struct{ name string }

// The closed set of events.
var (
	Started                  = Event{"started"}
	Stopping                 = Event{"stopping"}
	Stopped                  = Event{"stopped"}
	ConfigInvalid            = Event{"config_invalid"}
	EpochInvalid             = Event{"epoch_invalid"}
	StartupFailed            = Event{"startup_failed"}
	AttestationUnavailable   = Event{"attestation_unavailable"}
	SignerUnavailable        = Event{"signer_unavailable"}
	TelegramClientIDUnset    = Event{"telegram_client_id_unset"}
	ListenFailed             = Event{"listen_failed"}
	AttestationRefreshFailed = Event{"attestation_refresh_failed"}
	Panic                    = Event{"panic"}
)

// Counter is a monotonically increasing integer. Values exist only as the
// variables below.
type Counter struct {
	name string
	v    atomic.Int64
}

// Inc adds one.
func (c *Counter) Inc() { c.v.Add(1) }

// Value returns the current count.
func (c *Counter) Value() int64 { return c.v.Load() }

func newCounter(name string) *Counter {
	c := &Counter{name: name}
	all = append(all, c)
	return c
}

var all []*Counter

// The closed set of counters.
var (
	RPCBadEnvelope   = newCounter("rpc_bad_envelope") // undecryptable or malformed outer request
	RegisterOK       = newCounter("register_ok")
	ErrBadRequest    = newCounter("register_bad_request")
	ErrIDToken       = newCounter("register_id_token_invalid")
	ErrKeyBinding    = newCounter("register_key_binding_failed")
	ErrPop           = newCounter("register_pop_invalid")
	ErrPhoneShared   = newCounter("register_phone_not_shared")
	ErrPhoneAllowed  = newCounter("register_phone_not_allowed")
	ErrEpoch         = newCounter("register_epoch_not_active")
	ErrInternal      = newCounter("register_internal")
	JWKSFetchOK      = newCounter("jwks_fetch_ok")
	JWKSFetchFailed  = newCounter("jwks_fetch_failed")
	AttestRefreshOK  = newCounter("attestation_refresh_ok")
	AttestRefreshErr = newCounter("attestation_refresh_failed")
	Panics           = newCounter("panics")
)

var (
	mu  sync.Mutex
	out io.Writer = os.Stderr
)

// SetOutput redirects logging (tests).
func SetOutput(w io.Writer) {
	mu.Lock()
	out = w
	mu.Unlock()
}

func write(line string) {
	mu.Lock()
	defer mu.Unlock()
	io.WriteString(out, time.Now().UTC().Format(time.RFC3339)+" guestackd "+line+"\n")
}

// Log writes one event.
func Log(e Event) {
	if e.name == "" {
		return
	}
	write("event=" + e.name)
}

// LogCounters writes every counter on one line.
func LogCounters() {
	var b strings.Builder
	b.WriteString("counters")
	for _, c := range all {
		b.WriteString(" " + c.name + "=" + strconv.FormatInt(c.Value(), 10))
	}
	write(b.String())
}

// ReportCounters logs the counters every interval until ctx ends.
func ReportCounters(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			Go(LogCounters)
		}
	}
}

// Go runs f, turning a panic into the fixed Panic event. Every goroutine
// guestackd starts, and every request handler, runs through this or Recover.
func Go(f func()) {
	defer Recover()
	f()
}

// Recover must be deferred directly. It swallows a panic and records only the
// fixed event: the panic value is never printed.
func Recover() {
	if r := recover(); r != nil {
		Panics.Inc()
		Log(Panic)
	}
}
