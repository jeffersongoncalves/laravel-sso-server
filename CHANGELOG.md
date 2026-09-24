# Changelog

All notable changes to this project will be documented in this file.

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
