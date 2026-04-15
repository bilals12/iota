package sqliteutil

import "testing"

func TestFileURI(t *testing.T) {
	t.Parallel()
	if got, want := FileURI(""), ""; got != want {
		t.Errorf("empty: got %q want %q", got, want)
	}
	if got, want := FileURI(":memory:"), ":memory:"; got != want {
		t.Errorf(":memory:: got %q want %q", got, want)
	}
	if got := FileURI("/tmp/x.db"); got != "/tmp/x.db?_journal_mode=WAL&_busy_timeout=5000" {
		t.Errorf("file: got %q", got)
	}
	if got := FileURI("/tmp/x.db?mode=rwc"); got != "/tmp/x.db?mode=rwc" {
		t.Errorf("already has ?: got %q", got)
	}
}
