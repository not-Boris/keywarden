# Security Test Report

## How To Complete

1. Fill metadata fields and keep them aligned with the evidence run ID.
2. For each test row, set `Pass/Fail` to `PASS`, `FAIL`, `PARTIAL`, or `N/A`.
3. Put concrete observations in `Actual` (status code, rejection text, behavior).
4. Always link an evidence artifact path for each completed row.
5. Keep findings evidence-backed; avoid conclusions without artifacts.

## Metadata

Date (UTC):
Environment URL:
Commit:
Run ID:
Tester:

## Scope

- Authentication and session handling
- Authorization boundaries
- Token handling
- Input validation
- File/command safety
- WebSocket controls

## Test Cases

| ID | Area | Test | Expected | Actual | Pass/Fail | Evidence Path |
|---|---|---|---|---|---|---|
| SEC-01 | Input validation | Submit malformed SSH key payload | 4xx with validation error |  |  |  |
| SEC-02 | Auth bypass | Call admin API as non-admin | 403 |  |  |  |
| SEC-03 | Token misuse | Use revoked/invalid agent token | 401/403 |  |  |  |
| SEC-04 | Object permission | Access server not granted to user | 403 |  |  |  |
| SEC-05 | Session/CSRF | Unsafe method without CSRF/session validity | Blocked |  |  |  |
| SEC-06 | File handling | Upload invalid file/path content | Rejected safely |  |  |  |
| SEC-07 | Command injection | Shell input escaping checks | No command injection path |  |  |  |
| SEC-08 | WebSocket shell auth | Open shell WS without scope | Rejected |  |  |  |
| SEC-09 | Host key verification | Shell verifies host identity | Verified or documented gap |  |  |  |

## Findings

- High:
- Medium:
- Low:

## Follow-up Actions

- 
