package logs

import (
	"testing"
	"time"
)

func TestApplyNginxAccessParserSetsParsedTimestamp(t *testing.T) {
	event := NewEvent(time.Date(2026, time.April, 15, 18, 43, 7, 0, time.UTC))
	event.SourceKind = "file"
	event.Message = `192.168.2.40 - - [28/Jan/2026:17:43:43 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.0"`

	if !applyNginxAccessParser(&event) {
		t.Fatalf("expected nginx parser to match log line")
	}

	expected := "2026-01-28T17:43:43Z"
	if event.Timestamp != expected {
		t.Fatalf("expected parsed timestamp %s, got %s", expected, event.Timestamp)
	}
}

func TestParseJSONTimestampSupportsEpochMillis(t *testing.T) {
	event := NewEvent(time.Date(2026, time.April, 15, 18, 43, 7, 0, time.UTC))
	event.SourceKind = "file"
	event.Message = `{"timestamp":1700000000000,"message":"login event"}`

	if !applyJSONParser(&event) {
		t.Fatalf("expected json parser to parse payload")
	}

	expected := time.Unix(1700000000, 0).UTC().Format(time.RFC3339Nano)
	if event.Timestamp != expected {
		t.Fatalf("expected parsed timestamp %s, got %s", expected, event.Timestamp)
	}
}

func TestParseSyslogTimestampHandlesYearRollover(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 30, 0, time.UTC)
	parsed, ok := parseSyslogTimestamp("Dec 31 23:59:59", now)
	if !ok {
		t.Fatalf("expected syslog timestamp to parse")
	}
	if parsed.Year() != 2025 {
		t.Fatalf("expected year rollover to previous year, got %d", parsed.Year())
	}
}

func TestMaybeSetParsedTimestampSkipsJournalAndServiceSources(t *testing.T) {
	original := "2026-04-15T18:43:07Z"
	event := Event{
		Timestamp:  original,
		SourceKind: "service",
	}

	maybeSetParsedTimestamp(&event, time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))
	if event.Timestamp != original {
		t.Fatalf("expected service timestamp to remain unchanged")
	}
}
