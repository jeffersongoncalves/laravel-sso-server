---
name: sso-server-clients
description: Register, deactivate and maintain client applications of jeffersongoncalves/laravel-sso-server
---

# SSO Server Client Management

## When to use this skill

Use this skill when registering a new client app on the SSO server, handing its credentials to the client team, deactivating a client, or running key rotation and session pruning.

## Register a client

```bash
php artisan sso-server:client "Marketing Portal" https://marketing.example.com/sso/callback --slo=https://marketing.example.com/sso/slo-webhook
```

- `redirect_uri` must be the exact callback URL the client sends; matching is byte-for-byte.
- `--slo` is optional; without it the client gets no Single Logout webhooks.
- The command prints `client_id` (UUID) and `client_secret` (64 random characters). Hand them to the client app as `SSO_CLIENT_ID` / `SSO_CLIENT_SECRET` through a secure channel.

The secret is stored with the `encrypted` cast (the server needs it to sign HMAC payloads), so it can be recovered from the database with the app key. Treat database backups and `APP_KEY` accordingly, and never print the secret in logs or API responses.

## Deactivate a client

```php
use JeffersonGoncalves\SsoServer\Models\SsoClient;

SsoClient::where('client_id', $clientId)->firstOrFail()->update(['is_active' => false]);
```

An inactive client is rejected by `/sso/authorize`, `/sso/token`, `/sso/userinfo` and `/sso/logout`, and receives no SLO webhooks. Deleting the client instead also deletes its `sso_active_sessions` rows (cascade).

## Change a client's secret or URLs

There is no command for this yet; update the model directly:

```php
use Illuminate\Support\Str;

$client->update(['client_secret' => $secret = Str::random(64)]);
```

The client app must switch to the new secret at the same time: HMAC signatures made with the old one stop verifying immediately.

## Maintenance

```bash
php artisan sso-server:keys              # rotate the RS256 signing key (keeps keys.keep pairs, default 2)
php artisan sso-server:prune --hours=24  # delete sessions expired more than 24h ago
```

Keep `--keep` at 2 or more: tokens signed by the previous key must still verify until they expire.

## Logout paths

- **IdP logout**: logging out of the server guard revokes the user's sessions and sends the signed SLO webhook to every active client with a `slo_webhook_url`.
- **Client-initiated**: the client redirects the browser to `GET /sso/logout?client_id=...&token_hint=<access token issued to it>&post_logout_redirect_uri=...&state=...`. The server revokes the user's sessions, notifies the other clients, logs the IdP session out when it is the same user, and redirects back to a URI with the same origin as the client's `redirect_uri`.
- **Programmatic**: `SsoServer::logoutUser((string) $user->getAuthIdentifier());`
