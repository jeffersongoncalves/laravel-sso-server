# Changelog

All notable changes to this project will be documented in this file.

## 1.1.2 - 2026-10-28

Tests now load the package migrations with jeffersongoncalves/pest-plugin-database-migrations, in the order declared by the service provider, instead of copying the .php.stub files by hand. No runtime changes.

## 1.1.1 - 2026-10-10

### Fixed

- Key rotation: the newest key now always signs, even after two rotations within the same second. Key ids include microseconds (`YmdHisu-<random>`); existing keys keep working and sort before new ones, so no action is needed.

### Tests

- New security suite: forged tokens (alg none, alg confusion, path traversal kid, swapped sub), foreign issuer, expired tokens and codes, revoked clients, logout redirect origin checks, key pruning and Single Logout webhook retries. 13 → 28 tests.

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-sso-server/compare/1.1.0...1.1.1

## 1.1.0 - 2026-09-24

### Features

- `email_verified` claim in the JWT and `/sso/userinfo` (from `MustVerifyEmail` or `email_verified_at`, `false` otherwise). Clients must not link accounts by email unless it is `true`.
- `GET /sso/logout`: client-initiated (RP-initiated) federated logout. Requires a `token_hint` issued to the calling client (expired tokens accepted), revokes the user's sessions, sends the SLO webhook to the other clients, ends the IdP session when it belongs to the same user, and redirects to a same-origin `post_logout_redirect_uri` with `state`.
- Laravel Boost guideline and skills (`sso-server-setup`, `sso-server-clients`).

### Dependencies

- Dropped the direct `guzzlehttp/guzzle` requirement: Guzzle now follows `illuminate/http` (`^7.8.2 || ^8.0`), so Guzzle 8 installs.

### Docs

- `docs/architecture.md` protocol and integration contract (new §3.5), security policy.

Backward compatible with 1.0.0. Tested on PHP 8.4 + Laravel 13 against SQLite, MySQL and PostgreSQL.

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-sso-server/compare/1.0.0...1.1.0

## 1.0.0 - 2026-09-24

Initial release.

### Features

- Authorization Code + PKCE (S256 only) with anti-CSRF state and exact redirect_uri matching
- One-time authorization codes (60s TTL) consumed through an atomic cache add
- RS256 access tokens with kid-based key rotation and /.well-known/jwks.json
- /sso/userinfo with HMAC-SHA256 signed responses (X-SSO-Timestamp + X-SSO-Signature)
- Active session tracking with revocation on logout
- Back-channel Single Logout: queued, signed webhooks to every client with a session, triggered by the native Logout event
- SsoUserSerializerContract for custom claims (roles, permissions, tenant_id)
- Commands: sso-server:client, sso-server:keys, sso-server:prune

Tested on PHP 8.4 + Laravel 13 against SQLite, MySQL and PostgreSQL.

## [Unreleased]
