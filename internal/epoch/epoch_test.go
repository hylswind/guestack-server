package epoch

import (
	"testing"
	"time"

	"github.com/hylswind/guestack-server/internal/vectors"
)

type epochVectors struct {
	Description string       `json:"description"`
	Valid       []validEpoch `json:"valid"`
	Invalid     []string     `json:"invalid"`
}

type validEpoch struct {
	ID       string `json:"id"`
	Start    int64  `json:"epoch_start"`
	End      int64  `json:"epoch_end"`
	StartUTC string `json:"epoch_start_utc"`
	EndUTC   string `json:"epoch_end_utc"`
}

var vectorIDs = []string{
	"2026-12", // December → January
	"2027-01",
	"2027-02", // non-leap February
	"2028-02", // leap February
	"2100-02", // century, not a leap year
	"2000-02", // divisible by 400, leap year
	"1970-01",
	"9999-12", // last representable epoch
}

var invalidIDs = []string{
	"", "2026-13", "2026-00", "2026-1", "26-12", "2026/12", "2026-12-01",
	" 2026-12", "2026-12 ", "2026-12\n", "1969-12", "+2026-12", "2026-1a", "0000-01",
}

func TestVectors(t *testing.T) {
	if vectors.Update() {
		v := epochVectors{
			Description: "EPOCH_ID → [epoch_start, epoch_end) in Unix seconds, UTC calendar months. invalid: IDs the backend refuses at startup.",
			Invalid:     invalidIDs,
		}
		for _, id := range vectorIDs {
			w, err := Parse(id)
			if err != nil {
				t.Fatal(id, err)
			}
			v.Valid = append(v.Valid, validEpoch{
				ID: id, Start: w.Start, End: w.End,
				StartUTC: time.Unix(w.Start, 0).UTC().Format(time.RFC3339),
				EndUTC:   time.Unix(w.End, 0).UTC().Format(time.RFC3339),
			})
		}
		vectors.Write(t, "epoch.json", v)
	}

	var v epochVectors
	vectors.Load(t, "epoch.json", &v)
	if len(v.Valid) == 0 || len(v.Invalid) == 0 {
		t.Fatal("empty vectors")
	}
	for _, c := range v.Valid {
		w, err := Parse(c.ID)
		if err != nil || w.Start != c.Start || w.End != c.End {
			t.Errorf("%s: got %+v %v, want [%d, %d)", c.ID, w, err, c.Start, c.End)
		}
		// Independent check of the RFC 3339 forms, which reviewers read.
		if s := time.Unix(c.Start, 0).UTC().Format(time.RFC3339); s != c.StartUTC {
			t.Errorf("%s: start %s != %s", c.ID, s, c.StartUTC)
		}
		if e := time.Unix(c.End, 0).UTC().Format(time.RFC3339); e != c.EndUTC {
			t.Errorf("%s: end %s != %s", c.ID, e, c.EndUTC)
		}
	}
	for _, id := range v.Invalid {
		if _, err := Parse(id); err == nil {
			t.Errorf("%q: accepted", id)
		}
	}
}

func TestKnownBoundaries(t *testing.T) {
	// Fixed expectations written by hand, independent of the vector file.
	for _, c := range []struct {
		id         string
		start, end string
	}{
		{"2026-12", "2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z"},
		{"2028-02", "2028-02-01T00:00:00Z", "2028-03-01T00:00:00Z"},
		{"2027-02", "2027-02-01T00:00:00Z", "2027-03-01T00:00:00Z"},
	} {
		w, err := Parse(c.id)
		if err != nil {
			t.Fatal(err)
		}
		if got := time.Unix(w.Start, 0).UTC().Format(time.RFC3339); got != c.start {
			t.Errorf("%s start = %s", c.id, got)
		}
		if got := time.Unix(w.End, 0).UTC().Format(time.RFC3339); got != c.end {
			t.Errorf("%s end = %s", c.id, got)
		}
	}
	if d := mustParse(t, "2028-02"); d.End-d.Start != 29*86400 {
		t.Error("leap February is not 29 days")
	}
	if d := mustParse(t, "2027-02"); d.End-d.Start != 28*86400 {
		t.Error("February 2027 is not 28 days")
	}
}

func TestContains(t *testing.T) {
	w := mustParse(t, "2026-12")
	for _, c := range []struct {
		t    int64
		want bool
	}{
		{w.Start - 1, false},
		{w.Start, true},
		{w.End - 1, true},
		{w.End, false},
	} {
		if got := w.Contains(c.t); got != c.want {
			t.Errorf("Contains(%d) = %v", c.t, got)
		}
	}
}

func TestCompiledRequiresID(t *testing.T) {
	old := ID
	defer func() { ID = old }()
	ID = ""
	if _, err := Compiled(); err == nil {
		t.Error("empty ID accepted")
	}
	ID = "2026-12"
	if w, err := Compiled(); err != nil || w.ID != "2026-12" {
		t.Error(w, err)
	}
}

func mustParse(t *testing.T, id string) Window {
	t.Helper()
	w, err := Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	return w
}
