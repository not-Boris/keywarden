# Keywarden OIDC and Social Login Setup

This guide configures:
- OIDC client login (Authentik, Authelia, Keycloak, or other OIDC IdP)
- Social login (GitHub)

Security model implemented by Keywarden:
- External identities are mapped by immutable provider subject (`sub`/`uid`) and provider ID.
- User email is immutable after account creation.
- Login is denied if a provider later returns a different email for an already-linked identity.
- Optional group-to-admin mapping is available for OIDC.

## 1. Install and migrate

```bash
pip install -r requirements.txt
cd app
python manage.py migrate
```

## 2. Core auth mode

```env
# native | hybrid | oidc
KEYWARDEN_AUTH_MODE=hybrid
```

- `native`: username/password only
- `hybrid`: username/password + OIDC/social (recommended)
- `oidc`: force OIDC login only

## 3. OIDC client configuration (generic)

Use discovery endpoint (recommended):

```env
KEYWARDEN_OIDC_CLIENT_ID=keywarden
KEYWARDEN_OIDC_CLIENT_SECRET=replace-with-secret
KEYWARDEN_OIDC_DISCOVERY_ENDPOINT=https://idp.example.com/application/o/keywarden/.well-known/openid-configuration
KEYWARDEN_OIDC_ISSUER=https://idp.example.com/application/o/keywarden/
KEYWARDEN_OIDC_SCOPES=openid email profile groups
KEYWARDEN_OIDC_PROVIDER_ID=corporate-sso
KEYWARDEN_OIDC_REQUIRE_VERIFIED_EMAIL=true
KEYWARDEN_OIDC_EMAIL_CLAIM=email
KEYWARDEN_OIDC_EMAIL_VERIFIED_CLAIM=email_verified
KEYWARDEN_OIDC_USERNAME_CLAIM=preferred_username
KEYWARDEN_OIDC_GROUPS_CLAIM=groups

# Optional admin sync from IdP groups
KEYWARDEN_OIDC_SYNC_ADMIN_FROM_GROUPS=false
KEYWARDEN_OIDC_ADMIN_GROUPS=keywarden-admins,admins
KEYWARDEN_OIDC_ADMIN_DEMOTE_ON_MISS=false
```

Manual endpoint mode (if discovery is unavailable):

```env
KEYWARDEN_OIDC_CLIENT_ID=keywarden
KEYWARDEN_OIDC_CLIENT_SECRET=replace-with-secret
KEYWARDEN_OIDC_AUTHORIZATION_ENDPOINT=https://idp.example.com/oauth2/authorize
KEYWARDEN_OIDC_TOKEN_ENDPOINT=https://idp.example.com/oauth2/token
KEYWARDEN_OIDC_USER_ENDPOINT=https://idp.example.com/oauth2/userinfo
KEYWARDEN_OIDC_JWKS_ENDPOINT=https://idp.example.com/oauth2/jwks
```

Redirect URI to register in your IdP:

```text
https://<your-keywarden-domain>/oidc/callback/
```

## 4. IdP examples

## Authentik

- Create an OAuth2/OpenID Provider in Authentik.
- Client type: Confidential.
- Redirect URI: `https://<your-keywarden-domain>/oidc/callback/`
- Scopes: `openid email profile` (plus `groups` if using group mapping).

Example:

```env
KEYWARDEN_OIDC_CLIENT_ID=keywarden
KEYWARDEN_OIDC_CLIENT_SECRET=<authentik-secret>
KEYWARDEN_OIDC_DISCOVERY_ENDPOINT=https://auth.example.com/application/o/keywarden/.well-known/openid-configuration
KEYWARDEN_OIDC_ISSUER=https://auth.example.com/application/o/keywarden/
KEYWARDEN_OIDC_GROUPS_CLAIM=groups
```

## Authelia

- Configure an OIDC client in Authelia.
- Set redirect URI to `https://<your-keywarden-domain>/oidc/callback/`.
- Ensure `email` and `profile` claims are emitted.

Example:

```env
KEYWARDEN_OIDC_CLIENT_ID=keywarden
KEYWARDEN_OIDC_CLIENT_SECRET=<authelia-secret>
KEYWARDEN_OIDC_DISCOVERY_ENDPOINT=https://auth.example.com/.well-known/openid-configuration
KEYWARDEN_OIDC_ISSUER=https://auth.example.com
KEYWARDEN_OIDC_EMAIL_CLAIM=email
```

## Keycloak

- Create a Confidential client in a realm.
- Valid redirect URI: `https://<your-keywarden-domain>/oidc/callback/`
- Standard flow enabled.

Example:

```env
KEYWARDEN_OIDC_CLIENT_ID=keywarden
KEYWARDEN_OIDC_CLIENT_SECRET=<keycloak-secret>
KEYWARDEN_OIDC_DISCOVERY_ENDPOINT=https://id.example.com/realms/main/.well-known/openid-configuration
KEYWARDEN_OIDC_ISSUER=https://id.example.com/realms/main
KEYWARDEN_OIDC_GROUPS_CLAIM=groups
```

## 5. GitHub social provider

Enable GitHub by credentials (or explicit `*_ENABLED=true`).

```env
KEYWARDEN_SITE_ID=1
KEYWARDEN_SOCIAL_REQUIRE_VERIFIED_EMAIL=true

KEYWARDEN_SOCIAL_GITHUB_ENABLED=true
KEYWARDEN_SOCIAL_GITHUB_CLIENT_ID=<github-client-id>
KEYWARDEN_SOCIAL_GITHUB_CLIENT_SECRET=<github-secret>
```

Keywarden includes social auth URLs under:

```text
/accounts/sso/
```

Provider callback URL to register:
- GitHub: `https://<your-keywarden-domain>/accounts/sso/github/login/callback/`

Security behavior:
- Social auto-onboarding is disabled.
- Users must already exist in Keywarden and must link GitHub from `/accounts/profile/`.
- After linking, `Login with GitHub` is available as an additional login method.
- Local Keywarden email and GitHub email may differ; matching is by linked GitHub subject (`uid`).
- Native password reset/email verification are disabled for SSO-linked accounts and handled in the IdP.

## 6. Email immutability behavior

- Once a Keywarden user is created, email cannot be edited via API/admin/social/OIDC updates.
- If an IdP/social provider later reports a different email for the same external identity, login is blocked.
- This prevents account takeover via claim/email drift.

## 7. Optional OIDC admin mapping

To map IdP groups to Keywarden administrator:

```env
KEYWARDEN_OIDC_SYNC_ADMIN_FROM_GROUPS=true
KEYWARDEN_OIDC_ADMIN_GROUPS=keywarden-admins,platform-admins
KEYWARDEN_OIDC_GROUPS_CLAIM=groups
```

Demotion behavior (optional):

```env
KEYWARDEN_OIDC_ADMIN_DEMOTE_ON_MISS=true
```

When enabled, a previously promoted user is demoted to standard user if admin groups are no longer present.

## 8. Validation checklist

- Login page shows social buttons for enabled providers.
- `/oidc/authenticate/` starts IdP login.
- First GitHub login only succeeds for previously linked users.
- Repeat logins map to same local user via external identity subject.
- Changing provider email for the same subject causes login rejection.
