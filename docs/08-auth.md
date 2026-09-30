# 08 — Authentication

Sign-in uses one of two methods:

- **client certificate (mTLS)** — a full session right away, without password or TOTP;
- **password + second factor (TOTP)** — the second factor is optional, see below.

Permissions after sign-in — [20-permissions.md](20-permissions.md). Table columns — [03-database.md](03-database.md)
and `docs/INSTALL/schema.sql`.

## Data model

Identity is separated from sign-in methods:

- **`users`** — who the user is (username, email, display_name, is_active, session_ttl, theme, timezone,
  totp_required). A user has no role: permissions come from groups and personal grants.
- **`auth_identities`** — an external identity, several per user. `type`: `cert` | `oauth`;
  `provider`/`principal` NOT NULL (for cert `provider=''`), UNIQUE(type, provider, principal) — one CN
  cannot be bound to two users. `oauth` is in the schema, but there is no sign-in with it.
- **Credentials** — separate tables: `password_credentials` (Argon2id, `must_change`),
  `totp_credentials` (`secret_encrypted`, `confirmed_at`, `last_used_step` — anti-replay,
  `pending_secret_encrypted` — the candidate when replacing the app), `recovery_codes` (`code_hash`, `used_at`).
- **`sessions`** — the DB holds only the SHA-256 of the token; `stage` (`pending`|`full`), `pending_step`, `auth_type`,
  `remember`, `ip`, `user_agent`, `expires_at`.
- **`auth_throttle`** — sign-in attempt limiting.

## Client certificate (mTLS)

TLS verification of the client certificate is done by **Apache**; the panel trusts it and reads the environment variables
`SSL_CLIENT_VERIFY` and `SSL_CLIENT_S_DN_CN`.

1. `GET /login`: if `SSL_CLIENT_VERIFY eq 'SUCCESS'`, principal = CN (`SSL_CLIENT_S_DN_CN`).
2. It looks up `auth_identities` with `type='cert' AND provider='' AND principal=<CN> AND is_active=1` for an active
   user.
3. Found — a full session opens (`auth_type='cert'`, a persistent cookie with the user's TTL), redirect.
   Not found — the regular password sign-in page. There is no self-registration.

Required Apache directives (the shipped `etc/apache/dns-panel.conf` does not contain them — they are added to the TLS vhost):

```apache
SSLCACertificateFile /etc/ssl/panel/company-ca.crt
SSLVerifyClient      require      # or optional, if password sign-in must remain for those without a certificate
SSLVerifyDepth       2
SSLOptions           +StdEnvVars
```

For IP-based decisions (throttle, session) only `REMOTE_ADDR` is used; a proxy in front of the panel sets it via
`mod_remoteip`.

> Certificate sign-in has not been verified live: the stand has no client certificates.

Binding a certificate is an operator task: an identity in Settings → Users & access
(`POST /dns-api/users/:id/identities`) or `deploy/bootstrap-admin.pl --cert-cn "<CN>"` for the first administrator.

## Password and second factor

- Password — `password_credentials.password_hash` (Argon2id, t=3, m=19 MiB, p=1). An unknown user
  and a wrong password are indistinguishable (always one Argon2id check). `must_change=1` — a temporary password that
  must be changed at sign-in.
- TOTP — RFC 6238 (SHA1, 30 s, 6 digits, window ±1 step), compatible with Google/Microsoft Authenticator. The secret
  is encrypted with AES-256-GCM using the key from the file `auth.master_key_file` (`etc/panel.toml`). The accepted step is remembered
  (`last_used_step`) — a repeated code is rejected. The QR is rendered locally (`Imager::QRCode`).
- Recovery codes — 10 one-time `xxxxx-xxxxx`, SHA-256 in the DB.
- Attempts are limited: password — 5 per 15 min per (user, IP) pair, codes — 5 per 5 min per user; when
  exceeded, `429`.

Password sign-in is multi-step (`POST /login`, JSON `action`). Until the steps are completed the session is `pending`
(15 min), and neither the panel nor the API accepts it. The next step is chosen from the actual state (`_first_pending_step`):

| State | What sign-in asks for |
|-----------|---------------------|
| temporary password (`must_change`) | change the password (`password`) |
| app enrolled | a code (`totp_verify`) or a recovery code (`recovery_use`) |
| no app, but one is expected (`users.totp_required=1`) | enroll an app (`totp_begin` → `totp_confirm`: QR → code → full session + recovery codes) |
| no app and none expected | nothing: a full session right after the password |

`users.totp_required` is the only thing that distinguishes a reset from turning it off. Administrator actions (permission
`users.manage`, all in the audit log):

| Action | Route | What it does |
|----------|---------|------------|
| **Reset** — lost phone | `POST /dns-api/users/:id/totp/reset` | secret and codes deleted, `totp_required=1`, sessions revoked → the next sign-in leads to enrolling an app |
| **Turn off** | `DELETE /dns-api/users/:id/totp` | the same deletion, but `totp_required=0` → sign-in asks only for the password |
| **Require / Stop asking** | `PUT /dns-api/users/:id/totp/required` | the flag only; deletes nothing, does not touch sessions |

An administrator cannot enroll an app on someone else's behalf. If the only administrator has lost access —
`libexec/recover-access.pl --username U [--password [S]] [--reset-totp]` on the node itself.

## Sessions

- Cookie `session_token`: `HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS. In the DB — the SHA-256 of the token.
- The full session TTL is the personal policy `users.session_ttl`, otherwise the setting `auth.session_ttl` (default
  86400 s). "Remember this device" decides only whether the cookie survives closing the browser.
- Modifying requests to the API and to `/login` use CSRF double-submit: cookie `csrf_token` = header `X-CSRF-Token`.
- Every request to pages and `/dns-api/*` (except health) checks for a full session.
- `logout` closes the current session and clears the cookie.
- A session cannot be created on an HA STANDBY node: `/login` shows a link to the pair's service address.

## Personal account (Account)

A person manages only themselves: the id comes from the session and is not in the request (`/dns-api/account*`).

| Action | Specifics |
|----------|-------------|
| Password change | The current one is asked for. The session the change is made from stays; the others are closed. |
| Enabling / replacing the app | The previous app keeps working until the new one is confirmed with a code (candidate — `pending_secret_encrypted`). On confirmation new recovery codes are issued. |
| New recovery codes | Require a code from the app. |
| Turning off the second factor | With a code from the app; recovery codes are deleted, sessions are not closed. With `totp_required=1` there is no turn-off, neither on screen nor in the API. |
| Own sessions | The current one cannot be closed; the others — one by one or all at once. |

The Account header shows the groups the person belongs to.

### Appearance and time zone

`users.theme` and `users.timezone` (NULL = as in the browser). The server includes the theme (`<link>` in `header.pl` and on
the login page), so there is no flash of the wrong look. The dark theme is `main.css` itself; the others live in
`css/themes/` and override only the CSS variables in `:root`. "As in the browser" is `themes/auto.css`:
the light palette on `prefers-color-scheme: light`.

Besides the palette, a theme can set `--font-ui`, `--bg-pattern`, `--sheen`/`--sheen-soft` and `--bevel`. Patterns are
gradients or SVG right in the variable value; a theme has no external files. Button and badge color is set
via `background-color`, not `background:` — the shorthand would reset the `background-image` with the theme's sheen.
The list of themes is `functions::account_themes`; every theme in the list must have a palette file.

Time is stored in UTC. The server prints it as UTC with a label, and the browser converts it to the chosen zone. The zone
does not affect the schedule of background processes.
