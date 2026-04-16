package logs

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
)

const defaultLimit = 500
const initialFileTailBytes = 1 << 20

type Collector struct{}

type journalSource struct {
	ID             string
	Kind           string
	Unit           string
	Name           string
	Parser         string
	Category       string
	EventType      string
	IncludeMatches map[string][]string
	ExcludeMatches map[string][]string
}

type fileSource struct {
	ID        string
	Path      string
	Name      string
	Parser    string
	Category  string
	EventType string
}

var (
	syslogLinePattern  = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:\s*(.*)$`)
	nginxAccessPattern = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)\s+HTTP/[^"]+"\s+(\d{3})\s+(\S+)`)
	numericTimePattern = regexp.MustCompile(`^-?\d+(?:\.\d+)?$`)
)

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Collect(
	ctx context.Context,
	limit int,
	sources []SourceConfig,
	state map[string]SourceState,
) ([]Event, map[string]SourceState, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	journalSources, fileSources := normalizeSources(sources)
	nextState := cloneSourceState(state)
	events := make([]Event, 0, limit)
	seen := map[string]struct{}{}

	collectJournalByDefault := len(journalSources) == 0 && len(fileSources) == 0
	if collectJournalByDefault {
		journalSources = []journalSource{{
			ID:        "default-journal",
			Kind:      "journal",
			Name:      "journal",
			Parser:    "none",
			Category:  "system",
			EventType: "system",
		}}
	}

	for _, source := range journalSources {
		if len(events) >= limit {
			break
		}
		select {
		case <-ctx.Done():
			return events, nextState, ctx.Err()
		default:
		}
		current := nextState[source.ID]
		sourceEvents, sourceState, err := c.collectJournalSource(ctx, source, current, limit-len(events), collectJournalByDefault)
		if err != nil {
			return nil, state, err
		}
		nextState[source.ID] = sourceState
		events = appendUniqueEvents(events, sourceEvents, seen, limit)
	}

	if collectJournalByDefault && len(events) == 0 {
		source := journalSources[0]
		current := nextState[source.ID]
		if current.Cursor == "" {
			sourceEvents, sourceState, err := c.collectJournalSource(ctx, source, current, limit-len(events), false)
			if err == nil {
				nextState[source.ID] = sourceState
				events = appendUniqueEvents(events, sourceEvents, seen, limit)
			}
		}
	}

	if len(events) >= limit || len(fileSources) == 0 {
		return events, nextState, nil
	}

	var firstFileErr error
	for _, source := range fileSources {
		if len(events) >= limit {
			break
		}
		select {
		case <-ctx.Done():
			return events, nextState, ctx.Err()
		default:
		}
		current := nextState[source.ID]
		fileEvents, sourceState, err := collectFileSource(source, current, limit-len(events))
		if err != nil {
			if firstFileErr == nil {
				firstFileErr = fmt.Errorf("collect file source %s: %w", source.Path, err)
			}
			continue
		}
		nextState[source.ID] = sourceState
		events = appendUniqueEvents(events, fileEvents, seen, limit)
	}
	if len(events) == 0 && firstFileErr != nil {
		return events, nextState, firstFileErr
	}

	return events, nextState, nil
}

func (c *Collector) collectJournalSource(
	ctx context.Context,
	source journalSource,
	state SourceState,
	limit int,
	currentBootOnly bool,
) ([]Event, SourceState, error) {
	if limit <= 0 {
		return []Event{}, state, nil
	}
	j, err := sdjournal.NewJournal()
	if err != nil {
		return nil, state, err
	}
	defer j.Close()

	bootID := currentBootID()
	if currentBootOnly && bootID != "" {
		if err := j.AddMatch("_BOOT_ID=" + bootID); err != nil {
			return nil, state, err
		}
	}
	if source.Unit != "" {
		if err := j.AddMatch("_SYSTEMD_UNIT=" + source.Unit); err != nil {
			return nil, state, err
		}
	}

	// Always collect from tail and stop at the last seen cursor to prioritize
	// newest logs and avoid head-of-journal backlog blocking recent events.
	return c.collectJournalFromTail(ctx, j, source, state, limit, currentBootOnly, bootID)
}

func (c *Collector) collectJournalFromTail(
	ctx context.Context,
	j *sdjournal.Journal,
	source journalSource,
	state SourceState,
	limit int,
	currentBootOnly bool,
	bootID string,
) ([]Event, SourceState, error) {
	if err := j.SeekTail(); err != nil {
		return nil, state, err
	}
	events := make([]Event, 0, limit)
	nextState := state
	newestCursor := ""
	stopCursor := strings.TrimSpace(state.Cursor)
	for len(events) < limit {
		select {
		case <-ctx.Done():
			return events, nextState, ctx.Err()
		default:
		}
		n, err := j.Previous()
		if err != nil {
			return events, nextState, err
		}
		if n == 0 {
			break
		}
		entry, err := j.GetEntry()
		if err != nil {
			return events, nextState, err
		}
		if newestCursor == "" {
			newestCursor = entry.Cursor
		}
		if stopCursor != "" && entry.Cursor == stopCursor {
			break
		}
		if !journalEntryMatchesSource(entry.Fields, source, currentBootOnly, bootID) {
			continue
		}
		events = append(events, buildJournalEvent(entry, source))
	}
	if newestCursor != "" {
		nextState.Cursor = newestCursor
	}
	return events, nextState, nil
}

func buildJournalEvent(entry *sdjournal.JournalEntry, source journalSource) Event {
	event := fromEntry(entry)
	event.SourceKind = source.Kind
	event.SourceName = source.Name
	if source.Category != "" {
		event.Category = source.Category
	}
	if event.EventType == "" {
		if source.EventType != "" {
			event.EventType = source.EventType
		} else {
			event.EventType = defaultEventType(event.Category)
		}
	}
	if applied := applyParser(&event, source.Parser); applied {
		if event.EventType == "" {
			event.EventType = source.EventType
		}
	}
	return event
}

func journalEntryMatchesSource(fields map[string]string, source journalSource, currentBootOnly bool, bootID string) bool {
	if currentBootOnly && bootID != "" {
		if !strings.EqualFold(strings.TrimSpace(fields["_BOOT_ID"]), strings.TrimSpace(bootID)) {
			return false
		}
	}
	if source.Unit != "" && !strings.EqualFold(strings.TrimSpace(fields["_SYSTEMD_UNIT"]), strings.TrimSpace(source.Unit)) {
		return false
	}
	for key, values := range source.IncludeMatches {
		if !fieldMatchesAny(fields[key], values) {
			return false
		}
	}
	for key, values := range source.ExcludeMatches {
		if fieldMatchesAny(fields[key], values) {
			return false
		}
	}
	return true
}

func fieldMatchesAny(fieldValue string, values []string) bool {
	fieldValue = strings.TrimSpace(fieldValue)
	if fieldValue == "" {
		return false
	}
	for _, candidate := range values {
		if strings.EqualFold(fieldValue, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func collectFileSource(source fileSource, state SourceState, limit int) ([]Event, SourceState, error) {
	if limit <= 0 {
		return []Event{}, state, nil
	}
	file, err := os.Open(source.Path)
	if err != nil {
		if os.IsNotExist(err) {
			next := state
			next.Offset = 0
			next.Inode = 0
			return []Event{}, next, nil
		}
		return nil, state, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, state, err
	}
	size := info.Size()
	inode := fileInode(info)
	offset := state.Offset
	if offset < 0 {
		offset = 0
	}
	if state.Inode == 0 && state.Offset == 0 && size > initialFileTailBytes {
		offset = size - initialFileTailBytes
	}
	if state.Inode != 0 && inode != 0 && state.Inode != inode {
		offset = 0
	}
	if offset > size {
		offset = 0
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, state, err
	}

	reader := bufio.NewReader(file)
	current := offset
	if offset > 0 {
		skipped, skipErr := reader.ReadString('\n')
		current += int64(len(skipped))
		if skipErr != nil && skipErr != io.EOF {
			next := state
			next.Offset = current
			next.Inode = inode
			return nil, next, skipErr
		}
	}
	events := make([]Event, 0, limit)

	for len(events) < limit {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			lineStart := current
			current += int64(len(line))
			message := strings.TrimRight(line, "\r\n")
			if message != "" {
				event := NewEvent(time.Now())
				event.SourceKind = "file"
				event.SourceName = source.Name
				event.Category = source.Category
				event.EventType = source.EventType
				event.Message = compactWhitespace(message)
				event.Raw = message
				event.Fields = map[string]string{
					"file_path":   source.Path,
					"file_inode":  strconv.FormatUint(inode, 10),
					"file_offset": strconv.FormatInt(lineStart, 10),
				}
				_ = applyParser(&event, source.Parser)
				events = append(events, event)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			next := state
			next.Offset = current
			next.Inode = inode
			return events, next, err
		}
	}

	next := state
	next.Offset = current
	next.Inode = inode
	reverseEvents(events)
	return events, next, nil
}

func normalizeSources(sources []SourceConfig) ([]journalSource, []fileSource) {
	journalSources := make([]journalSource, 0, len(sources))
	fileSources := make([]fileSource, 0, len(sources))
	for _, source := range sources {
		kind := strings.ToLower(strings.TrimSpace(source.Kind))
		id := sourceStateID(source)
		parser := normalizeParser(source.Parser)
		includeMatches := normalizeMatches(source.IncludeMatches)
		excludeMatches := normalizeMatches(source.ExcludeMatches)

		switch kind {
		case "service":
			unit := strings.TrimSpace(source.ServiceUnit)
			if unit == "" {
				unit = strings.TrimSpace(source.Name)
			}
			if unit == "" {
				continue
			}
			category := strings.TrimSpace(source.Category)
			if category == "" {
				category = defaultCategoryForService(unit)
			}
			eventType := strings.TrimSpace(source.EventType)
			if eventType == "" {
				eventType = defaultEventType(category)
			}
			name := strings.TrimSpace(source.Name)
			if name == "" {
				name = unit
			}
			includeMatches["_SYSTEMD_UNIT"] = appendUniqueStrings(includeMatches["_SYSTEMD_UNIT"], unit)
			journalSources = append(journalSources, journalSource{
				ID:             id,
				Kind:           "service",
				Unit:           unit,
				Name:           name,
				Parser:         parser,
				Category:       category,
				EventType:      eventType,
				IncludeMatches: includeMatches,
				ExcludeMatches: excludeMatches,
			})
		case "journal":
			category := strings.TrimSpace(source.Category)
			if category == "" {
				category = "system"
			}
			eventType := strings.TrimSpace(source.EventType)
			if eventType == "" {
				eventType = defaultEventType(category)
			}
			name := strings.TrimSpace(source.Name)
			if name == "" {
				name = "journal"
			}
			journalSources = append(journalSources, journalSource{
				ID:             id,
				Kind:           "journal",
				Unit:           strings.TrimSpace(source.ServiceUnit),
				Name:           name,
				Parser:         parser,
				Category:       category,
				EventType:      eventType,
				IncludeMatches: includeMatches,
				ExcludeMatches: excludeMatches,
			})
		case "file":
			path := strings.TrimSpace(source.FilePath)
			if path == "" {
				path = strings.TrimSpace(source.Name)
			}
			if path == "" {
				continue
			}
			category := strings.TrimSpace(source.Category)
			if category == "" {
				category = "file"
			}
			eventType := strings.TrimSpace(source.EventType)
			if eventType == "" {
				eventType = "file.line"
			}
			name := strings.TrimSpace(source.Name)
			if name == "" {
				name = path
			}
			fileSources = append(fileSources, fileSource{
				ID:        id,
				Path:      path,
				Name:      name,
				Parser:    parser,
				Category:  category,
				EventType: eventType,
			})
		}
	}
	return journalSources, fileSources
}

func sourceStateID(source SourceConfig) string {
	explicit := strings.TrimSpace(source.SourceID)
	if explicit != "" {
		return explicit
	}
	parts := []string{
		strings.ToLower(strings.TrimSpace(source.Kind)),
		strings.TrimSpace(source.Name),
		strings.TrimSpace(source.ServiceUnit),
		strings.TrimSpace(source.FilePath),
		strings.ToLower(strings.TrimSpace(source.Parser)),
		strings.TrimSpace(source.Category),
		strings.TrimSpace(source.EventType),
		encodeMatchMap(source.IncludeMatches),
		encodeMatchMap(source.ExcludeMatches),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "src-" + hex.EncodeToString(sum[:8])
}

func normalizeParser(parser string) string {
	switch strings.ToLower(strings.TrimSpace(parser)) {
	case "syslog", "nginx_access", "json":
		return strings.ToLower(strings.TrimSpace(parser))
	default:
		return "none"
	}
}

func normalizeMatches(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return map[string][]string{}
	}
	out := map[string][]string{}
	for key, values := range in {
		keyText := strings.TrimSpace(key)
		if keyText == "" {
			continue
		}
		cleanValues := make([]string, 0, len(values))
		for _, value := range values {
			valueText := strings.TrimSpace(value)
			if valueText == "" {
				continue
			}
			cleanValues = append(cleanValues, valueText)
		}
		if len(cleanValues) == 0 {
			continue
		}
		out[keyText] = appendUniqueStrings(nil, cleanValues...)
	}
	return out
}

func appendUniqueStrings(base []string, values ...string) []string {
	seen := map[string]struct{}{}
	out := append([]string{}, base...)
	for _, value := range out {
		seen[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		key := strings.ToLower(normalized)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func cloneSourceState(in map[string]SourceState) map[string]SourceState {
	out := map[string]SourceState{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func appendUniqueEvents(dst []Event, src []Event, seen map[string]struct{}, limit int) []Event {
	for _, event := range src {
		if len(dst) >= limit {
			break
		}
		key := eventDedupKey(event)
		if key != "" {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
		}
		dst = append(dst, event)
	}
	return dst
}

func reverseEvents(events []Event) {
	for left, right := 0, len(events)-1; left < right; left, right = left+1, right-1 {
		events[left], events[right] = events[right], events[left]
	}
}

func eventDedupKey(event Event) string {
	if len(event.Fields) > 0 {
		if cursor := strings.TrimSpace(event.Fields["journal_cursor"]); cursor != "" {
			return "journal:" + cursor
		}
		path := strings.TrimSpace(event.Fields["file_path"])
		inode := strings.TrimSpace(event.Fields["file_inode"])
		offset := strings.TrimSpace(event.Fields["file_offset"])
		if path != "" && offset != "" {
			return "file:" + path + ":" + inode + ":" + offset
		}
	}
	if event.SourceKind != "" && event.SourceName != "" && event.Timestamp != "" && event.Message != "" {
		return strings.Join([]string{"fallback", event.SourceKind, event.SourceName, event.Timestamp, event.Message}, "|")
	}
	return ""
}

func applyParser(event *Event, parser string) bool {
	switch normalizeParser(parser) {
	case "json":
		return applyJSONParser(event)
	case "nginx_access":
		return applyNginxAccessParser(event)
	case "syslog":
		return applySyslogParser(event)
	default:
		return false
	}
}

func applyJSONParser(event *Event) bool {
	payload := map[string]any{}
	if err := json.Unmarshal([]byte(event.Message), &payload); err != nil {
		return false
	}
	if event.Fields == nil {
		event.Fields = map[string]string{}
	}
	for key, value := range payload {
		keyText := strings.TrimSpace(key)
		if keyText == "" {
			continue
		}
		event.Fields["json."+keyText] = fmt.Sprint(value)
	}
	if parsedTimestamp, ok := parseJSONTimestamp(payload); ok {
		maybeSetParsedTimestamp(event, parsedTimestamp)
	}
	for _, candidate := range []string{"message", "msg", "log"} {
		if value, ok := payload[candidate]; ok {
			message := compactWhitespace(fmt.Sprint(value))
			if message != "" {
				event.Message = message
				break
			}
		}
	}
	if event.Username == "" {
		for _, candidate := range []string{"username", "user"} {
			if value, ok := payload[candidate]; ok {
				event.Username = strings.TrimSpace(fmt.Sprint(value))
				if event.Username != "" {
					break
				}
			}
		}
	}
	if event.SourceIP == "" {
		for _, candidate := range []string{"source_ip", "ip", "remote_addr", "client_ip"} {
			if value, ok := payload[candidate]; ok {
				event.SourceIP = strings.TrimSpace(fmt.Sprint(value))
				if event.SourceIP != "" {
					break
				}
			}
		}
	}
	return true
}

func applyNginxAccessParser(event *Event) bool {
	matches := nginxAccessPattern.FindStringSubmatch(event.Message)
	if len(matches) == 0 {
		return false
	}
	if parsedTimestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", strings.TrimSpace(matches[2])); err == nil {
		maybeSetParsedTimestamp(event, parsedTimestamp)
	}
	if event.SourceIP == "" {
		event.SourceIP = strings.TrimSpace(matches[1])
	}
	if event.Fields == nil {
		event.Fields = map[string]string{}
	}
	event.Fields["nginx.time_local"] = matches[2]
	event.Fields["nginx.method"] = matches[3]
	event.Fields["nginx.path"] = matches[4]
	event.Fields["nginx.status"] = matches[5]
	event.Fields["nginx.body_bytes_sent"] = matches[6]
	if event.EventType == "" || event.EventType == "file.line" || event.EventType == "system" {
		event.EventType = "http.access"
	}
	if event.Category == "system" {
		event.Category = "access"
	}
	return true
}

func applySyslogParser(event *Event) bool {
	message := strings.TrimSpace(event.Message)
	if message == "" {
		return false
	}
	if strings.HasPrefix(message, "<") {
		if end := strings.Index(message, ">"); end > 1 {
			priorityText := strings.TrimSpace(message[1:end])
			if priorityValue, err := strconv.Atoi(priorityText); err == nil {
				severity := priorityValue % 8
				if event.Priority == "" {
					event.Priority = strconv.Itoa(severity)
				}
				message = strings.TrimSpace(message[end+1:])
			}
		}
	}
	matches := syslogLinePattern.FindStringSubmatch(message)
	if len(matches) == 0 {
		return false
	}
	if parsedTimestamp, ok := parseSyslogTimestamp(matches[1], time.Now()); ok {
		maybeSetParsedTimestamp(event, parsedTimestamp)
	}
	if event.Hostname == "" {
		event.Hostname = strings.TrimSpace(matches[2])
	}
	identifier := strings.TrimSpace(matches[3])
	pid := strings.TrimSpace(matches[4])
	parsedMessage := compactWhitespace(matches[5])
	if parsedMessage != "" {
		event.Message = parsedMessage
	}
	if event.Fields == nil {
		event.Fields = map[string]string{}
	}
	if identifier != "" {
		event.Fields["syslog_identifier"] = identifier
	}
	if pid != "" {
		event.Fields["syslog_pid"] = pid
	}
	if event.SourceName == "" && identifier != "" {
		event.SourceName = identifier
	}
	if event.SourceIP == "" || event.Username == "" {
		_, username, sourceIP, _ := parseMessage(event.Category, event.Message)
		if event.Username == "" {
			event.Username = username
		}
		if event.SourceIP == "" {
			event.SourceIP = sourceIP
		}
	}
	return true
}

func maybeSetParsedTimestamp(event *Event, timestamp time.Time) {
	if timestamp.IsZero() {
		return
	}
	// Journal entries already provide canonical timestamps from journald.
	if event.SourceKind != "" && event.SourceKind != "file" {
		return
	}
	event.Timestamp = timestamp.UTC().Format(time.RFC3339Nano)
}

func parseJSONTimestamp(payload map[string]any) (time.Time, bool) {
	for _, candidate := range []string{
		"@timestamp",
		"timestamp",
		"time",
		"ts",
		"datetime",
		"date",
		"event_time",
	} {
		value, ok := payload[candidate]
		if !ok {
			continue
		}
		if parsed, ok := parseTimestampValue(value); ok {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func parseTimestampValue(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case string:
		return parseTimestampString(typed)
	case float64:
		return parseNumericTimestamp(strconv.FormatFloat(typed, 'f', -1, 64))
	case json.Number:
		return parseNumericTimestamp(typed.String())
	case int:
		return parseNumericTimestamp(strconv.FormatInt(int64(typed), 10))
	case int8:
		return parseNumericTimestamp(strconv.FormatInt(int64(typed), 10))
	case int16:
		return parseNumericTimestamp(strconv.FormatInt(int64(typed), 10))
	case int32:
		return parseNumericTimestamp(strconv.FormatInt(int64(typed), 10))
	case int64:
		return parseNumericTimestamp(strconv.FormatInt(typed, 10))
	case uint:
		return parseNumericTimestamp(strconv.FormatUint(uint64(typed), 10))
	case uint8:
		return parseNumericTimestamp(strconv.FormatUint(uint64(typed), 10))
	case uint16:
		return parseNumericTimestamp(strconv.FormatUint(uint64(typed), 10))
	case uint32:
		return parseNumericTimestamp(strconv.FormatUint(uint64(typed), 10))
	case uint64:
		if typed > math.MaxInt64 {
			return time.Time{}, false
		}
		return parseNumericTimestamp(strconv.FormatUint(typed, 10))
	default:
		return time.Time{}, false
	}
}

func parseTimestampString(value string) (time.Time, bool) {
	candidate := strings.TrimSpace(value)
	if candidate == "" {
		return time.Time{}, false
	}
	if numericTimePattern.MatchString(candidate) {
		if parsed, ok := parseNumericTimestamp(candidate); ok {
			return parsed, true
		}
	}

	layoutsWithZone := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05Z07:00",
		"02/Jan/2006:15:04:05 -0700",
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822Z,
		time.RFC822,
		time.RFC850,
		time.RubyDate,
		time.UnixDate,
	}
	for _, layout := range layoutsWithZone {
		if parsed, err := time.Parse(layout, candidate); err == nil {
			return parsed, true
		}
	}

	layoutsWithoutZone := []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05,999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02",
		time.ANSIC,
	}
	for _, layout := range layoutsWithoutZone {
		if parsed, err := time.ParseInLocation(layout, candidate, time.Local); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func parseNumericTimestamp(value string) (time.Time, bool) {
	candidate := strings.TrimSpace(value)
	if candidate == "" {
		return time.Time{}, false
	}
	if strings.Contains(candidate, ".") {
		numericValue, err := strconv.ParseFloat(candidate, 64)
		if err != nil {
			return time.Time{}, false
		}
		return parseUnixFloatTimestamp(numericValue), true
	}
	numericValue, err := strconv.ParseInt(candidate, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return parseUnixIntTimestamp(numericValue), true
}

func parseUnixIntTimestamp(value int64) time.Time {
	absValue := value
	if absValue < 0 {
		absValue = -absValue
	}
	switch {
	case absValue >= 1e18:
		return time.Unix(0, value)
	case absValue >= 1e15:
		return time.Unix(0, value*int64(time.Microsecond))
	case absValue >= 1e12:
		return time.Unix(0, value*int64(time.Millisecond))
	default:
		return time.Unix(value, 0)
	}
}

func parseUnixFloatTimestamp(value float64) time.Time {
	absValue := math.Abs(value)
	switch {
	case absValue >= 1e18:
		return time.Unix(0, int64(value))
	case absValue >= 1e15:
		return time.Unix(0, int64(value*float64(time.Microsecond)))
	case absValue >= 1e12:
		return time.Unix(0, int64(value*float64(time.Millisecond)))
	default:
		seconds, fraction := math.Modf(value)
		return time.Unix(int64(seconds), int64(fraction*float64(time.Second)))
	}
}

func parseSyslogTimestamp(value string, now time.Time) (time.Time, bool) {
	candidate := compactWhitespace(value)
	if candidate == "" {
		return time.Time{}, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	nowLocal := now.In(time.Local)
	parsed, err := time.ParseInLocation("Jan 2 15:04:05 2006", fmt.Sprintf("%s %d", candidate, nowLocal.Year()), time.Local)
	if err != nil {
		return time.Time{}, false
	}
	// Syslog timestamps omit the year; pull back one year if parsing lands
	// in the future due to year rollover.
	if parsed.After(nowLocal.Add(24 * time.Hour)) {
		parsed = parsed.AddDate(-1, 0, 0)
	}
	return parsed, true
}

func fileInode(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return stat.Ino
}

func encodeMatchMap(in map[string][]string) string {
	if len(in) == 0 {
		return ""
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		values := append([]string{}, in[key]...)
		sort.Strings(values)
		parts = append(parts, key+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, ";")
}

func currentBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func fromEntry(entry *sdjournal.JournalEntry) Event {
	ts := time.Unix(0, int64(entry.RealtimeTimestamp)*int64(time.Microsecond))
	event := NewEvent(ts)
	fields := entry.Fields
	unit := fields["_SYSTEMD_UNIT"]
	rawMessage := strings.TrimSpace(fields["MESSAGE"])
	identifier := fields["SYSLOG_IDENTIFIER"]
	pid := fields["_PID"]

	event.Unit = unit
	event.Message = compactJournalLine(identifier, pid, rawMessage)
	if rawMessage != "" && rawMessage != event.Message {
		event.Raw = rawMessage
	}
	event.Priority = fields["PRIORITY"]
	event.Hostname = fields["_HOSTNAME"]
	event.Fields = compactJournalFields(fields, entry.Cursor)

	event.Category = categorize(unit, identifier, fields)
	event.EventType, event.Username, event.SourceIP, event.SessionID = parseMessage(event.Category, rawMessage)
	if event.EventType == "" {
		event.EventType = defaultEventType(event.Category)
	}
	return event
}

func compactJournalLine(identifier string, pid string, message string) string {
	normalizedMessage := compactWhitespace(message)
	identifier = strings.TrimSpace(identifier)
	pid = strings.TrimSpace(pid)

	if normalizedMessage == "" {
		if identifier != "" && pid != "" {
			return identifier + "[" + pid + "]"
		}
		return identifier
	}
	if identifier != "" && pid != "" {
		return identifier + "[" + pid + "]: " + normalizedMessage
	}
	if identifier != "" {
		return identifier + ": " + normalizedMessage
	}
	return normalizedMessage
}

func compactWhitespace(value string) string {
	if value == "" {
		return ""
	}
	return strings.Join(strings.Fields(value), " ")
}

func compactJournalFields(fields map[string]string, cursor string) map[string]string {
	compact := map[string]string{}
	if cursor != "" {
		compact["journal_cursor"] = cursor
	}
	if bootID := strings.TrimSpace(fields["_BOOT_ID"]); bootID != "" {
		compact["boot_id"] = bootID
	}
	if transport := strings.TrimSpace(fields["_TRANSPORT"]); transport != "" {
		compact["transport"] = transport
	}
	if comm := strings.TrimSpace(fields["_COMM"]); comm != "" {
		compact["comm"] = comm
	}
	if exe := strings.TrimSpace(fields["_EXE"]); exe != "" {
		compact["exe"] = exe
	}
	if pid := strings.TrimSpace(fields["_PID"]); pid != "" {
		compact["pid"] = pid
	}
	if uid := strings.TrimSpace(fields["_UID"]); uid != "" {
		compact["uid"] = uid
	}
	if gid := strings.TrimSpace(fields["_GID"]); gid != "" {
		compact["gid"] = gid
	}
	if len(compact) == 0 {
		return nil
	}
	return compact
}

func categorize(unit string, identifier string, fields map[string]string) string {
	switch {
	case unit == "sshd.service" || unit == "ssh.service" || identifier == "sshd":
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

func defaultCategoryForService(unit string) string {
	switch strings.ToLower(unit) {
	case "sshd.service", "ssh.service":
		return "access"
	case "sudo.service":
		return "auth"
	case "systemd-networkd.service", "networkmanager.service":
		return "network"
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
	case "file":
		return "file.line"
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
