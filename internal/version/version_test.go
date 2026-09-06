package version

import "testing"

// Version must come from the VERSION file, trimmed of the trailing newline a
// text file normally ends with -- not the raw embedded bytes.
func TestVersionIsTrimmed(t *testing.T) {
	if Version == "" {
		t.Fatal("Version is empty")
	}
	if Version != versionFile && Version+"\n" != versionFile {
		t.Fatalf("Version %q does not match VERSION file content %q", Version, versionFile)
	}
	if Version[len(Version)-1] == '\n' {
		t.Fatalf("Version was not trimmed: %q", Version)
	}
}
