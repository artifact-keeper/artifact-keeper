# SSO sign-in is bound to the browser that started it

Since 1.12.0 (#5486) an OIDC or SAML sign-in can only be completed by the
browser that started it. Before, the OIDC `state`, the SAML AuthnRequest id and
the exchange code handed to the web UI were bearer values: an attacker could
start a sign-in, authenticate at the identity provider as themselves, and send a
victim's browser to the callback (or to `/callback?code=…`), signing the victim
in to the attacker's account (login CSRF). The victim's uploads, tokens and
settings then landed in the attacker's account.

## How it works

`GET /api/v1/auth/sso/oidc/{id}/login` and `GET /api/v1/auth/sso/saml/{id}/login`
set a cookie in the browser:

```
ak_sso_bind_<prefix>=<64 hex digits>; HttpOnly; [Secure;] SameSite=Lax; Path=/api/v1/auth/sso; Max-Age=600
```

Its value is an HMAC of the login's `state` (SAML: AuthnRequest id) under the
server's `JWT_SECRET`, so every replica can check it and nobody without the
secret can mint one. Each sign-in gets its own cookie, so two sign-ins in one
browser (two tabs, the silent `prompt=none` probe) do not interfere. `Secure`
follows the same rule as the session cookies (`AK_ENFORCE_HTTPS` or
`X-Forwarded-Proto: https`, never in `ENVIRONMENT=development`).

| step | requires |
|---|---|
| OIDC callback (`/oidc/callback`, `/oidc/{id}/callback`) | the cookie for its `state`; checked before the state is consumed |
| SAML ACS (`POST /saml/{id}/acs`) | nothing new: it is a cross-site POST, which carries no `SameSite=Lax` cookie. It validates the assertion and answers `303 See Other` to `/api/v1/auth/sso/complete?code=…` **without** setting a session. An account with TOTP enrolled (#5484) is sent with `303` straight to the web UI's `/callback?code=…` instead: its code carries only the TOTP challenge |
| `GET /api/v1/auth/sso/complete?code=…` (SAML) | the cookie the exchange code was minted for; sets the session cookies and redirects to the web UI's `/callback?code=…` |
| `POST /api/v1/auth/sso/exchange` | the cookie the exchange code was minted for; clears it on success |

A refusal is `401` with code `AUTH_ERROR` ("This sign-in was not started in this
browser …"), counted in `ak_auth_failures_total` like any other refused SSO
sign-in. A refused OIDC callback is also audited as `LOGIN_FAILED` with
`details.reason = "sso_browser_binding"`. A refused request does not consume the
state or the exchange code. Both stay single-use and expire as before (10
minutes for the state, 60 seconds for the code).

## Command-line sign-in (`client=cli`)

`ak auth login --sso oidc:<id>` (or `saml:<id>`) starts the sign-in itself and
prints the identity provider's URL for the user to open in a browser. That
browser never saw the login response, so it has no binding cookie. The CLI
asks for its own mode by adding `client=cli` to the login URL:

- the login response is the same redirect with the same `ak_sso_bind_*`
  cookie, which the CLI keeps;
- the `state` (SAML: AuthnRequest id) starts with `cli-` (SAML: `_cli-`), so
  the callback (SAML: the ACS) does not look for the cookie in the browser;
- instead of signing the browser in, the callback answers `200` with a
  `text/plain` page that shows the exchange code (`Cache-Control: no-store`,
  `Referrer-Policy: no-referrer`). It sets no cookies;
- the CLI sends the code to `POST /api/v1/auth/sso/exchange` with its cookie.
  Without that cookie the code is refused, so the browser that shows it can't
  use it, and neither can anyone it is sent to.

A sign-in started in this mode never leaves a session in the browser it is
completed in, so it can't be used for a login CSRF either. Any other `client`
value is refused with `400`.

## What operators need to know

- **Reverse proxies** must pass `/api/v1/auth/sso/*` through unchanged, as the
  cookie is scoped to that path. A proxy that serves the API under another
  prefix needs to rewrite the cookie's `Path` too.
- **IdP-initiated SAML** stays unsupported (a response must answer a pending
  AuthnRequest), and `RelayState` is still not used: the AuthnRequest id the
  response answers identifies the sign-in.
- **Rolling upgrade from 1.11.x**: a sign-in started on a 1.11.x replica (no
  cookie) and completed on a 1.12.0 replica is refused, and so is an exchange
  code minted by a 1.11.x replica. A SAML ACS on 1.12.0 redirects to
  `/complete`, which a 1.11.x replica does not serve. Users who hit this during
  the rollout sign in again.
- **Other clients** of `/api/v1/auth/sso/exchange` must send the cookies the
  sign-in set (a browser does this on its own).
- **The CLI**: an `ak` release without `client=cli` support can't finish an
  OIDC or SAML browser sign-in against 1.12.0. Its callback is refused in the
  browser, because the CLI started the sign-in and the browser has no cookie.
  LDAP sign-in (`--sso ldap:<id>`), API tokens and the device flow
  (`--oidc-device`) don't use these endpoints and are unaffected.
