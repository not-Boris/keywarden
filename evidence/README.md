# Evidence Pack

This folder is for dissertation evidence that can be regenerated on demand.

## Quick Start

Run from repo root:

```bash
bash scripts/collect_evidence.sh
```

Optional custom run id:

```bash
bash scripts/collect_evidence.sh 2026-04-16-baseline
```

Outputs are written to `evidence/runs/<run-id>/`.

To autofill templates for an existing run:

```bash
bash scripts/autofill_evidence_templates.sh <run-id>
```

To capture UI screenshots for an existing run:

```bash
bash scripts/capture_ui_screenshots.sh <run-id>
```

To include screenshot capture during evidence collection:

```bash
KEYWARDEN_EVIDENCE_CAPTURE_SCREENSHOTS=1 bash scripts/collect_evidence.sh <run-id>
```

## What Is Collected

- Git and environment snapshot (`meta/`)
- Docker Compose state and container runtime info (`runtime/`)
- Django test execution output (`tests/`)
- Coverage summary + XML when available (`tests/coverage-report.txt`, `tests/coverage-xml.xml`)
- Log extracts and endpoint/status summaries (`logs/`)
- Derived operational metrics and summary (`evaluation/`)
- RBAC/role-claim grep evidence (`docs/`)
- Copy of diagram sources and report templates (`diagrams/`, `templates/`)
- Autofilled template versions in each run (`templates/*.md`)
- Optional automated UI screenshots (`screenshots/`)

## Operational Metrics

The collector now derives evaluation-friendly metrics from `agent-access` logs:

- heartbeat intervals per server
- endpoint/status distributions per server
- heartbeat error-to-recovery timings
- markdown summary for direct report inclusion

Artifacts are written to `evidence/runs/<run-id>/evaluation/`.

## Diagram Sources

Mermaid sources live in `evidence/diagrams/`:

- `architecture.mmd`
- `deployment.mmd`
- `erd.mmd`
- `access-sync-flow.mmd`

These are plain text and version-controlled, so they are easy to revise and re-render.

## Manual Evidence Templates

Templates for remaining manual work are in `evidence/templates/`:

- browser test matrix
- security test report
- standards checklist (OWASP/NIST-oriented)
