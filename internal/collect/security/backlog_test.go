package security

import "testing"

func TestParseJournalSecurity(t *testing.T) {
	auth, selinux, apparmor := ParseJournalSecurity("sshd: Failed password for x\n" +
		"type=AVC avc: denied { read }\n" + "apparmor=\"DENIED\" operation=\"open\"\n" + "normal message\n")
	if auth != 1 || selinux != 1 || apparmor != 1 {
		t.Fatalf("got auth=%d selinux=%d apparmor=%d", auth, selinux, apparmor)
	}
}

func TestParseSessionsAndCoreDumps(t *testing.T) {
	if got := ParseSessions("alice pts/0\n\nbob pts/1\n"); got != 2 {
		t.Fatalf("sessions=%d", got)
	}
	if got := ParseCoreDumps("No coredumps found.\n"); got != 0 {
		t.Fatalf("core dumps=%d", got)
	}
	if got := ParseCoreDumps("a\nb\n"); got != 2 {
		t.Fatalf("core dumps=%d", got)
	}
}
