package logs

import "time"

type Event struct {
	Timestamp  string            `json:"timestamp"`
	Category   string            `json:"category"`
	EventType  string            `json:"event_type"`
	SourceKind string            `json:"source_kind,omitempty"`
	SourceName string            `json:"source_name,omitempty"`
	Unit       string            `json:"unit,omitempty"`
	Priority   string            `json:"priority,omitempty"`
	Hostname   string            `json:"hostname,omitempty"`
	Username   string            `json:"username,omitempty"`
	Principal  string            `json:"principal,omitempty"`
	SourceIP   string            `json:"source_ip,omitempty"`
	SessionID  string            `json:"session_id,omitempty"`
	Message    string            `json:"message,omitempty"`
	Raw        string            `json:"raw,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
}

func NewEvent(ts time.Time) Event {
	return Event{Timestamp: ts.UTC().Format(time.RFC3339Nano)}
}

type SourceConfig struct {
	SourceID       string
	Kind           string
	Name           string
	ServiceUnit    string
	FilePath       string
	Parser         string
	IncludeMatches map[string][]string
	ExcludeMatches map[string][]string
	Category       string
	EventType      string
}

type SourceState struct {
	Cursor string `json:"cursor,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Inode  uint64 `json:"inode,omitempty"`
}
