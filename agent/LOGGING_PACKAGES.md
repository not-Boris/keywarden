# Logging Package Options

This agent already uses a library approach for journald (`github.com/coreos/go-systemd/v22/sdjournal`) and does not shell out to `journalctl` in normal collection paths.

## Current (keep)

- `github.com/coreos/go-systemd/v22/sdjournal`
  - Direct journal access from Go.
  - Cursor-based reads map well to incremental shipping.
- `github.com/coreos/go-systemd/v22/dbus` (candidate add-on)
  - Read systemd unit state/metadata (`ListUnitsByNames`, unit properties) for richer service context.

## Good external collectors (if we want hardened third-party gathering)

- Fluent Bit
  - `systemd` input plugin for journald, plus mature filtering/parsing/routing outputs.
  - Strong choice when we want a small footprint daemon dedicated to log forwarding.
- Vector
  - `journald` source + transforms (VRL) for compact line formatting before shipping.
  - Good if we want expressive local transforms and multiple downstream sinks.
- OpenTelemetry Collector distributions with journald receiver support (for example Splunk OTel distro)
  - Useful if we want logs + metrics + traces through one pipeline.

## Parser packages (when we need deeper line parsing)

- `github.com/influxdata/go-syslog/v3`
  - RFC3164/RFC5424 syslog parsing for file or stream logs.
- `github.com/elastic/go-grok`
  - Pattern-based parsing when message formats vary by service.

## Practical direction

1. Keep `go-systemd` for now and add optional `dbus` lookups for service status enrichment.
2. If we need host-agnostic, independently hardened collection, run Fluent Bit or Vector and ingest normalized JSON lines in the agent/server.
3. Reserve heavier parsing packages (`go-syslog`, `go-grok`) for specific source formats that require structured extraction beyond current compact line ingestion.
