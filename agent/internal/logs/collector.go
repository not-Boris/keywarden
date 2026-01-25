package logs

import (
	"context"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
)

const defaultLimit = 500

type Collector struct {
	matches []string
}

func NewCollector() *Collector {
	return &Collector{matches: defaultMatches()}
}

func (c *Collector) Collect(ctx context.Context, cursor string, limit int) ([]Event, string, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	j, err := sdjournal.NewJournal()
	if err != nil {
		return nil, "", err
	}
	defer j.Close()

	for i, match := range c.matches {
		if i > 0 {
			if err := j.AddDisjunction(); err != nil {
				return nil, "", err
			}
		}
		if err := j.AddMatch(match); err != nil {
			return nil, "", err
		}
	}

	if cursor != "" {
		if err := j.SeekCursor(cursor); err == nil {
			_, _ = j.Next()
		}
	} else {
		_ = j.SeekTail()
		_, _ = j.Next()
	}

	var events []Event
	var nextCursor string
	for len(events) < limit {
		select {
		case <-ctx.Done():
			return events, nextCursor, ctx.Err()
		default:
		}
		n, err := j.Next()
		if err != nil {
			return events, nextCursor, err
		}
		if n == 0 {
			break
		}
		entry, err := j.GetEntry()
		if err != nil {
			return events, nextCursor, err
		}
		event := fromEntry(entry)
		events = append(events, event)
		nextCursor = entry.Cursor
	}

	return events, nextCursor, nil
}

func defaultMatches() []string {
	return []string{
		"_SYSTEMD_UNIT=sshd.service",
		"_SYSTEMD_UNIT=sudo.service",
		"_SYSTEMD_UNIT=systemd-networkd.service",
		"_SYSTEMD_UNIT=NetworkManager.service",
		"_SYSTEMD_UNIT=systemd-logind.service",
		"_TRANSPORT=kernel",
	}
}

func fromEntry(entry *sdjournal.JournalEntry) Event {
	ts := time.Unix(0, int64(entry.RealtimeTimestamp)*int64(time.Microsecond))
	event := NewEvent(ts)
	fields := entry.Fields
	unit := fields["_SYSTEMD_UNIT"]
	message := fields["MESSAGE"]
	identifier := fields["SYSLOG_IDENTIFIER"]

	event.Unit = unit
	event.Message = message
	event.Priority = fields["PRIORITY"]
	event.Hostname = fields["_HOSTNAME"]
	event.Fields = fields

	event.Category = categorize(unit, identifier, fields)
	event.EventType, event.Username, event.SourceIP, event.SessionID = parseMessage(event.Category, message)
	if event.EventType == "" {
		event.EventType = defaultEventType(event.Category)
	}
	return event
}

func categorize(unit string, identifier string, fields map[string]string) string {
	switch {
	case unit == "sshd.service" || identifier == "sshd":
		return "access"
	case unit == "sudo.service" || identifier == "sudo":
		return "auth"
	case unit == "systemd-networkd.service" || identifier == "NetworkManager":
		return "network"
	case fields["_TRANSPORT"] == "kernel":
		return "system"
	default:
		return "system"
	}
}

func defaultEventType(category string) string {
	switch category {
	case "access":
		return "ssh"
	case "auth":
		return "auth"
	case "network":
		return "network"
	default:
		return "system"
	}
}

func parseMessage(category string, msg string) (eventType string, username string, sourceIP string, sessionID string) {
	if msg == "" {
		return "", "", "", ""
	}
	lower := strings.ToLower(msg)
	if category == "access" {
		switch {
		case strings.Contains(lower, "accepted"):
			eventType = "ssh.login.success"
			username = extractBetween(msg, "for ", " from")
			sourceIP = extractBetween(msg, "from ", " port")
		case strings.Contains(lower, "failed password"):
			eventType = "ssh.login.fail"
			username = extractBetween(msg, "for ", " from")
			sourceIP = extractBetween(msg, "from ", " port")
		case strings.Contains(lower, "session opened"):
			eventType = "ssh.session.open"
			username = extractBetween(msg, "for user ", " by")
		case strings.Contains(lower, "session closed"):
			eventType = "ssh.session.close"
			username = extractBetween(msg, "for user ", " by")
		}
	}
	return eventType, strings.TrimSpace(username), strings.TrimSpace(sourceIP), strings.TrimSpace(sessionID)
}

func extractBetween(msg string, start string, end string) string {
	startIdx := strings.Index(msg, start)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(start)
	rest := msg[startIdx:]
	endIdx := strings.Index(rest, end)
	if endIdx == -1 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:endIdx])
}
