package sqliteutil

import "strings"

// FileURI returns a SQLite connection string with WAL journal and a busy timeout
// so concurrent handlers (e.g. parallel SQS message processing) see fewer
// "database is locked" errors. In-memory databases are returned unchanged.
func FileURI(path string) string {
	if path == "" || path == ":memory:" {
		return path
	}
	if strings.Contains(path, "?") {
		return path
	}
	return path + "?_journal_mode=WAL&_busy_timeout=5000"
}
