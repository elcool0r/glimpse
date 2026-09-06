package timesync

import (
	"math"
	"testing"
)

func TestParseTimedatectl(t *testing.T) {
	got := ParseTimedatectl("NTPSynchronized=yes\nNTP=no\nSystemClockSynchronized=yes\n")
	if got.Synchronized == nil || !*got.Synchronized || got.NTPEnabled == nil || *got.NTPEnabled {
		t.Fatalf("got %#v", got)
	}
}

func TestParseChronyc(t *testing.T) {
	got := ParseChronyc("Stratum         : 3\nLast offset     : -0.000234 seconds\nLeap status     : Normal\n")
	if got.Stratum != 3 || got.OffsetMillis == nil || math.Abs(*got.OffsetMillis+.234) > 0.000001 || got.Synchronized == nil || !*got.Synchronized {
		t.Fatalf("got %#v", got)
	}
}

func TestParseChronycUnsynchronized(t *testing.T) {
	got := ParseChronyc("Leap status     : Not synchronised\n")
	if got.Synchronized == nil || *got.Synchronized {
		t.Fatalf("got %#v", got)
	}
}
