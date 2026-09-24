---
name: sso-server-setup
description: Install, configure and troubleshoot jeffersongoncalves/laravel-sso-server as the central SSO identity provider
---

# SSO Server Setup

## When to use this skill

Use this skill when installing `jeffersongoncalves/laravel-sso-server` in the identity app, configuring its guard, cache, queue and keys, or diagnosing why authorization, token exchange, userinfo or Single Logout fails.

## Prerequisites to check

- The guard users sign in with on the IdP (`sso-server.guard`, default `web`). Its user provider resolves the `sub` claim.
- A cache store with atomic `add()` (redis, memcached or database) for one-time authorization codes.
- A queue worker for `DispatchSingleLogoutJob` (connection/queue via `SSO_SERVER_SLO_CONNECTION` / `SSO_SERVER_SLO_QUEUE`).
- A login route: `/sso/authorize` runs behind `auth`, so guests are sent to it and come back.

## Install

```bash
composer require jeffersongoncalves/laravel-sso-server
php artisan vendor:publish --tag=sso-server-config
php artisan vendor:publish --tag=sso-server-migrations
php artisan migrate
php artisan sso-server:keys
```

Migrations create `sso_clients` first, then `sso_active_sessions` (foreign key to `sso_clients`, cascade on delete).

`sso-server:keys` writes `{kid}.key` (mode 0600) and `{kid}.pub` into `sso-server.keys.path` (default `storage/sso-server`). The directory must be writable by PHP and shared between servers.

On Windows (e.g. Herd), if key generation fails with an OpenSSL error, set `SSO_SERVER_OPENSSL_CONF` to an `openssl.cnf` path (`sso-server.keys.openssl_config`).

## Configuration (`config/sso-server.php`)

```php
'issuer' => env('SSO_SERVER_ISSUER'),          // "iss" claim; null = app.url
'guard' => env('SSO_SERVER_GUARD', 'web'),
'routes' => [
    'enabled' => true,
    'prefix' => 'sso',
    'authorize_middleware' => ['web'],          // authorize (+ "auth:{guard}") and logout
    'api_middleware' => ['throttle:60,1'],      // token, userinfo, JWKS
],
'code_ttl' => 60,
'token_ttl' => 3600,
'cache_store' => env('SSO_SERVER_CACHE_STORE'),
'keys' => ['path' => storage_path('sso-server'), 'keep' => 2, 'openssl_config' => env('SSO_SERVER_OPENSSL_CONF')],
'serializer' => DefaultUserSerializer::class,
'slo' => ['connection' => ..., 'queue' => ..., 'timeout' => 10],
```

If `email_verified` should reflect real verification, make the user model implement `Illuminate\Contracts\Auth\MustVerifyEmail` (or keep an `email_verified_at` column).

## Scheduling

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

Schedule::command('sso-server:prune --hours=24')->daily();
```

Rotate the signing key periodically with `sso-server:keys`; `keys.keep` (default 2) keeps the previous public key in the JWKS so tokens signed before the rotation still verify.

## Verify

1. `curl -s https://idp.test/.well-known/jwks.json` returns 200 with `keys[]` entries (`kty: RSA`, `alg: RS256`, `use: sig`, `kid`). The JWKS path is not under the `sso` prefix.
2. Signed in on the IdP, opening `/sso/authorize` with no parameters returns HTTP 400 (as a guest you are sent to the login page first).
3. `php artisan route:list --name=sso-server` lists `authorize`, `token`, `userinfo`, `logout` and `jwks`.

## Troubleshooting

- **"No SSO signing key found"**: run `php artisan sso-server:keys`, or the keys directory is not shared with this server.
- **`invalid_grant` on `/sso/token`**: the code is older than `code_ttl`, was already used (any attempt burns it), belongs to another client, or `redirect_uri` / PKCE verifier differ from the authorize request.
- **`/sso/userinfo` returns 401 after a while**: the token expired or the user logged out (the session row was deleted). Clients must sign in again.
- **Clients never receive SLO webhooks**: no queue worker running, the client is inactive, or it has no `slo_webhook_url`. Failed deliveries are retried 5 times.
