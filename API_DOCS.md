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
