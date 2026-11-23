// Package epoch holds the one epoch this build serves (spec/identifiers.md).
//
// ID is set at link time with
//
//	-ldflags "-X github.com/hylswind/guestack-server/internal/epoch.ID=2026-12"
//
// so it is part of the measured binary. It is never read from the environment.
package epoch

import (
	"errors"
	"regexp"
	"strconv"
	"time"
)

// ID is the UTC year-month this build serves, e.g. "2026-12". Set by the linker.
var ID string

// ErrInvalid means the ID is not a valid YYYY-MM.
var ErrInvalid = errors.New("epoch: invalid EPOCH_ID")

// Window is one UTC calendar month: Start ≤ t < End, in Unix seconds.
type Window struct {
	ID         string
	Start, End int64
}

var idPattern = regexp.MustCompile(`^([0-9]{4})-(0[1-9]|1[0-2])$`)

// Parse validates id (YYYY-MM, year 1970–9999) and derives its window.
func Parse(id string) (Window, error) {
	m := idPattern.FindStringSubmatch(id)
	if m == nil {
		return Window{}, ErrInvalid
	}
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	if year < 1970 {
		return Window{}, ErrInvalid
	}
	start := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	return Window{ID: id, Start: start.Unix(), End: end.Unix()}, nil
}

// Compiled returns the window of the ID set at link time. It fails if the
// binary was built without a valid ID.
func Compiled() (Window, error) { return Parse(ID) }

// Contains reports whether Start ≤ t < End.
func (w Window) Contains(t int64) bool { return w.Start <= t && t < w.End }
