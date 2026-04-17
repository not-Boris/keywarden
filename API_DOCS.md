# API docs

The API v1 interactive documentation is served by Django Ninja at `/api/v1/docs`.

What it provides:
- Swagger UI for all v1 routes, request/response schemas, and example payloads.
- Try-it-out support for GET/POST/PATCH/DELETE.

Authentication:
- Session auth works in the browser, but unsafe requests require CSRF.
- For API testing, use JWT: add `Authorization: Bearer <access_token>`.

Notes:
- Base URL for v1 endpoints is `/api/v1`.
- Admin-only routes return `403 Forbidden` when the token user is not staff/superuser.

Example: update server display name (admin-only)

PATCH `/api/v1/servers/{server_id}`

```json
{
  "display_name": "Keywarden Prod"
}
```

## SSH user certificates (OpenSSH CA)

Keywarden signs user SSH keys with an OpenSSH certificate authority. The flow is:
- User uploads a public key (`POST /api/v1/keys`).
- Server signs the key using the active user CA.
- Certificate is stored server-side and can be downloaded by the user.

Endpoints:
- `POST /api/v1/keys/{key_id}/certificate` issues (or re-issues) a certificate.
- `GET /api/v1/keys/{key_id}/certificate` downloads the certificate.
- `GET /api/v1/keys/{key_id}/certificate.sha256` downloads a sha256 hash file.

Agent endpoints (mTLS client certificate; cert is issued during enrollment, token retained only for migration compatibility):
- `GET /api/v1/agent/servers/{server_id}/ssh-ca` returns the CA public key for agent install.
- `GET /api/v1/agent/servers/{server_id}/accounts` returns account + system username (no raw keys).

Configuration:
- `KEYWARDEN_USER_CERT_VALIDITY_DAYS` controls certificate lifetime (default: 30 days).
- `KEYWARDEN_ACCOUNT_USERNAME_TEMPLATE` controls account name derivation.

Note: `ssh-keygen` must be available on the Keywarden server to sign certificates.
