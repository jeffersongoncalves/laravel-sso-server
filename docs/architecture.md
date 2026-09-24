# Architecture & Integration Contract

This document defines the cryptographic architecture, communication protocol, and integration contract implemented in `jeffersongoncalves/laravel-sso-server` (v1.1.x). Changes since 1.0.0 are additive: the `email_verified` claim and the client-initiated logout endpoint (§3.5). Clients such as `jeffersongoncalves/laravel-sso-client` must follow it exactly.

Route URIs below use the default prefix `sso` (`sso-server.routes.prefix`). Clients should keep the server URLs configurable.

---

## 1. High-Level Flow

```
                  +---------------------------------------+
                  |               Browser                 |
                  +---------------------------------------+
                    |                                   ^
   1. GET /sso/     |                                   | 2. Redirect with
      authorize     |                                   |    code & state
      (PKCE+state)  v                                   |
                  +---------------------------------------+
                  |         laravel-sso-server            |
                  +---------------------------------------+
                    ^                 |                 |
     3. POST        |                 | 4. GET          | 5. POST (queued job)
        /sso/token  |                 |    /sso/userinfo|    SLO webhook
        (swap code) |                 |    (Bearer JWT) |    (HMAC signed)
                    v                 v                 v
                  +---------------------------------------+
                  |         laravel-sso-client            |
                  +---------------------------------------+
```

---

## 2. Cryptographic Protocol & Guarantees

- **Token signing (RS256):** access tokens are JWTs signed with OpenSSL RSA 2048-bit keys. The header carries `alg: RS256`, `typ: JWT` and `kid`. The active public key and retained historical keys are served at `/.well-known/jwks.json`.
- **Key storage & rotation:** keys live in `sso-server.keys.path` (default `storage/sso-server`) as `{kid}.key` and `{kid}.pub`, where `kid` is `YmdHis-random6`. The lexicographically highest `kid` signs new tokens; `php artisan sso-server:keys` rotates and keeps `keys.keep` pairs (default 2) so tokens signed before a rotation still verify.
- **HMAC signatures:** `/sso/userinfo` responses and Single Logout webhooks are signed with HMAC-SHA256, keyed with the client's raw `client_secret`, over `"{timestamp}.{raw body}"`. The server stores `client_secret` encrypted (not hashed) precisely so it can sign.
- **Anti-replay guarantees:**
  - Authorization codes are 64 random characters with a 60-second TTL (`sso-server.code_ttl`), stored in cache by their SHA-256 hash.
  - Codes are consumed atomically on the first exchange attempt via `Cache::add("{key}:used")`, burning the code even if the request then fails validation. Use a cache store with atomic `add()` (redis, memcached, database).
  - The server sends a timestamp with every signature; the **client** must reject stale timestamps (e.g. `abs(now - timestamp) <= 300`) and, for webhooks, already-seen `jti` values.

---

## 3. API Endpoints

### 3.1 Authorization Endpoint

Initiated by a browser redirect from the client.

- **Method / URI:** `GET /sso/authorize`
- **Middleware:** `web`, `auth:{guard}` (guests are sent to the server's login page and come back)
- **Query parameters:**

| Parameter | Rule |
|---|---|
| `client_id` | required; registered, active client UUID |
| `redirect_uri` | required; exact string match with the client's registered `redirect_uri` |
| `code_challenge` | required; `base64url(sha256(code_verifier))` without padding — 43 characters, `[A-Za-z0-9_-]` |
| `code_challenge_method` | required; must be `S256` (`plain` is rejected) |
| `state` | required; 16–255 characters |
| `response_type` | optional; if present, must be `code` |

**Responses:**

- Invalid parameters, unknown/inactive client, or `redirect_uri` mismatch: `HTTP 400` rendered on the server. It never redirects to an unverified URI.
- Success: `HTTP 302` to `{redirect_uri}?code={code}&state={state}` (`&` is used if `redirect_uri` already has a query string).

PKCE challenge in PHP:

```php
$challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
```

### 3.2 Token Exchange Endpoint

Server-to-server call from the client backend. Must happen right after the callback: the code expires in 60 seconds and works once.

- **Method / URI:** `POST /sso/token`
- **Middleware:** `throttle:60,1`
- **Headers:** `Accept: application/json`; body as `application/json` or form-encoded
- **Request body:**

```json
{
  "grant_type": "authorization_code",
  "client_id": "9d901844-3323-455b-8012-70b77b7db22e",
  "client_secret": "<client secret>",
  "code": "<code from the callback>",
  "code_verifier": "<43-128 character verifier kept in the client session>",
  "redirect_uri": "https://client.test/sso/callback"
}
```

**Validation order:** the code is consumed first; then `client_id` + `client_secret` (`hash_equals`); then the code must belong to that client, `redirect_uri` must match the one used at authorization, and `base64url(sha256(code_verifier))` must equal the stored `code_challenge`.

**Success (`HTTP 200`, `Cache-Control: no-store`):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIwMjYwOTI0MTUwMDAwLWEyYjNjNCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

There is **no** `user` property: user claims live inside the JWT and are available from `/sso/userinfo`. Each issued token creates an `sso_active_sessions` row (`client_id`, `user_id`, `sha256(access_token)`, `expires_at`).

**Errors:**

| Status | `error` | Cause |
|---|---|---|
| 400 | `invalid_request` | missing or malformed parameter (including `grant_type`) |
| 401 | `invalid_client` | unknown/inactive client or wrong `client_secret` |
| 400 | `invalid_grant` | code expired, already used or issued to another client; `redirect_uri` or PKCE mismatch; user no longer exists |

Error bodies are `{"error": "...", "error_description": "..."}`. There is no refresh token in 1.x.

**JWT claims:** `iss` (`sso-server.issuer`, default the server's `APP_URL`), `sub` (user id, always a string), `aud` (`client_id`), `iat`, `nbf`, `exp`, `jti`, plus the claims returned by the configured `SsoUserSerializerContract` (default `name`, `email`, `email_verified`). Reserved claims always win over serializer claims.

**`email_verified` (boolean, since 1.1.0):** `true` only when the user model implements `MustVerifyEmail` and `hasVerifiedEmail()` is true, or, without that interface, when `email_verified_at` is filled. Anything else is `false`. Clients must not link an existing local account by `email` unless `email_verified` is `true`; otherwise anyone who registers that address on the IdP takes over the local account. Custom serializers should keep emitting this claim.

Clients validating tokens locally must check the signature against the JWKS (`alg` must be `RS256`), `iss`, `aud === client_id`, `exp` and `nbf`. Local validation does not see server-side logouts; revocation reaches clients through the SLO webhook.

### 3.3 User Profile Endpoint

Server-to-server call returning the user's current claims.

- **Method / URI:** `GET /sso/userinfo`
- **Middleware:** `throttle:60,1`
- **Headers:** `Authorization: Bearer {access_token}`, `Accept: application/json`

**Validation:** RS256 signature, `iss`, expiration, and an existing, unexpired `sso_active_sessions` row for the token. After a server-side logout the row is gone and the endpoint returns `HTTP 401`.

**Success (`HTTP 200`, `Cache-Control: no-store`):**

- Headers: `X-SSO-Timestamp: 1790280000`, `X-SSO-Signature: <hmac_sha256("{timestamp}.{raw body}", client_secret)>`
- Body (serializer claims plus `sub`):

```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "email_verified": true,
  "sub": "12345"
}
```

Verify the signature over the raw response body; do not re-encode the JSON.

**Failure:** `HTTP 401` with `{"error": "invalid_token"}` and `WWW-Authenticate: Bearer error="invalid_token"`.

### 3.4 Public Keys (JWKS)

- **Method / URI:** `GET /.well-known/jwks.json` (not prefixed)
- **Response (`HTTP 200`, `Cache-Control: public, max-age=300`):**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "20260924150000-a2b3c4",
      "n": "u1g8...",
      "e": "AQAB"
    }
  ]
}
```

Clients should cache the key set and refetch once when they meet an unknown `kid`.

### 3.5 Client-Initiated Logout (since 1.1.0)

Federated logout started by a user clicking "Log out" in a client app. Modeled on OpenID Connect RP-Initiated Logout: it is a **browser redirect**, so the IdP's session cookie comes along and the IdP session can be ended too.

- **Method / URI:** `GET /sso/logout`
- **Middleware:** `web` (no `auth`: the user may already be logged out of the IdP)
- **Query parameters:**

| Parameter | Rule |
|---|---|
| `client_id` | required; active client |
| `token_hint` | required; an access token this server issued **to this client** (`aud === client_id`). Signature and issuer are checked; **expiry and revocation are not**, so the client can send the last token it holds. |
| `post_logout_redirect_uri` | optional; absolute URL with the same origin (scheme, host, port) as the client's registered `redirect_uri` |
| `state` | optional; up to 255 characters, echoed back |

Requiring `token_hint` means a client can only log out users it actually signed in, never an arbitrary user id.

**Behavior:**

1. Invalid parameters, unknown/inactive client, bad or foreign `token_hint`, or a `post_logout_redirect_uri` from another origin: `HTTP 400` on the server, no redirect.
2. All `sso_active_sessions` of the token's `sub` are deleted, and the SLO webhook (§4) goes to every **other** client of that user. The initiating client gets no webhook: it already logged the user out locally.
3. If the browser's IdP session belongs to that same `sub`, it is logged out, invalidated, and the CSRF token regenerated. A different user signed in on that browser is left alone.
4. Redirect to `post_logout_redirect_uri` (plus `?state=...` / `&state=...` when `state` was sent), or to the IdP's `/` when no URI was given.

Client flow: destroy the local session first, then redirect the browser to `/sso/logout` with the stored access token.

---

## 4. Single Logout (SLO)

Triggered by `Illuminate\Auth\Events\Logout` on the configured guard (`sso-server.guard`), by the client-initiated logout endpoint (§3.5, which skips the initiating client), or manually with `SsoServer::logoutUser($userId)`:

1. All `sso_active_sessions` rows of that user are deleted, so `/sso/userinfo` rejects their tokens from then on.
2. Every distinct client linked to those rows that is active and has a `slo_webhook_url` gets a queued `DispatchSingleLogoutJob`. Rows that already expired but were not pruned yet are included, because a client's local session can outlive the access token (`sso-server:prune` removes rows expired more than 24 hours ago).
3. A `UserLoggedOutEvent` is fired on the server.

Each job tries 5 times (backoff 10s, 30s, 60s, 300s) with a 10-second HTTP timeout. Any non-2xx response or timeout counts as a failure.

### Webhook request

- **Method:** `POST {slo_webhook_url}`
- **Headers:**
  - `Content-Type: application/json`
  - `X-SSO-Timestamp: 1790280000`
  - `X-SSO-Signature: <hmac_sha256("{timestamp}.{raw body}", client_secret)>`
- **Body:**

```json
{
  "event": "logout",
  "sub": "12345",
  "aud": "9d901844-3323-455b-8012-70b77b7db22e",
  "iat": 1790280000,
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Client handling rules

1. Expose the webhook route outside CSRF protection and outside `auth`.
2. Check `abs(now - X-SSO-Timestamp) <= 300`.
3. Check `hash_equals(hash_hmac('sha256', $timestamp.'.'.$request->getContent(), $clientSecret), $signature)`.
4. Check `event === "logout"` and `aud === client_id`.
5. Record the `jti` in cache (e.g. `Cache::add("sso-client:jti:{$jti}", true, 600)`); if it was already there, skip processing but still answer 2xx.
6. Invalidate every local session of the user whose server `sub` equals the received `sub` (the client must store the server `sub` when the user signs in).
7. Respond with any 2xx status (`200` or `204`).

For logout started from a client app, see §3.5.
