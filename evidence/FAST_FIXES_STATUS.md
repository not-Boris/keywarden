# Fast Fix Status

This tracks the fastest issues and where reproducible evidence now lives.

## Completed in this pass

- RBAC wording aligned to implemented roles (`administrator`, `user`, alias `admin`):
  - [users.py](/opt/compose/keywarden/app/keywarden/api/routers/users.py#L15)
  - [access.py](/opt/compose/keywarden/app/keywarden/api/routers/access.py#L168)
  - [agent.py](/opt/compose/keywarden/app/keywarden/api/routers/agent.py#L214)
  - [API_DOCS.md](/opt/compose/keywarden/API_DOCS.md#L39)
- Repeatable evidence collector added:
  - [collect_evidence.sh](/opt/compose/keywarden/scripts/collect_evidence.sh)
- Automated operational metrics extraction added:
  - [summarize_operational_metrics.sh](/opt/compose/keywarden/scripts/summarize_operational_metrics.sh)
- Diagram sources added (Mermaid):
  - [architecture.mmd](/opt/compose/keywarden/evidence/diagrams/architecture.mmd)
  - [deployment.mmd](/opt/compose/keywarden/evidence/diagrams/deployment.mmd)
  - [erd.mmd](/opt/compose/keywarden/evidence/diagrams/erd.mmd)
  - [access-sync-flow.mmd](/opt/compose/keywarden/evidence/diagrams/access-sync-flow.mmd)
- Manual evidence templates added:
  - [browser-matrix.md](/opt/compose/keywarden/evidence/templates/browser-matrix.md)
  - [security-test-report.md](/opt/compose/keywarden/evidence/templates/security-test-report.md)
  - [standards-checklist.md](/opt/compose/keywarden/evidence/templates/standards-checklist.md)

## Generated baseline run

- Run folder: [20260416T213000Z](/opt/compose/keywarden/evidence/runs/20260416T213000Z)
- Summary: [SUMMARY.md](/opt/compose/keywarden/evidence/runs/20260416T213000Z/SUMMARY.md)
- Test output: [django-tests.txt](/opt/compose/keywarden/evidence/runs/20260416T213000Z/tests/django-tests.txt)
- Test failure summary: [django-tests-failures-summary.txt](/opt/compose/keywarden/evidence/runs/20260416T213000Z/tests/django-tests-failures-summary.txt)
- Coverage text report: [coverage-report.txt](/opt/compose/keywarden/evidence/runs/20260416T213000Z/tests/coverage-report.txt)
- Coverage XML: [coverage-xml.xml](/opt/compose/keywarden/evidence/runs/20260416T213000Z/tests/coverage-xml.xml)
- Agent endpoint counts: [agent-endpoint-status-counts.txt](/opt/compose/keywarden/evidence/runs/20260416T213000Z/logs/agent-endpoint-status-counts.txt)
- Operational evaluation summary: [operational-summary.md](/opt/compose/keywarden/evidence/runs/20260416T225300Z/evaluation/operational-summary.md)

## Still pending (not fast, or partly manual)

- Screenshot capture for dissertation figures (manual execution, now templated).
- Deep security hardening tasks (shell host-key model, strict mTLS enforcement, SPOF mitigation, push-based revocation).
