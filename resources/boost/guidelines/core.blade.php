## Laravel SSO Server

The `jeffersongoncalves/laravel-sso-server` package turns a Laravel app into the central identity provider (IdP) for other Laravel apps: Authorization Code + PKCE, RS256 access tokens with a JWKS endpoint and key rotation, HMAC-signed userinfo responses, and back-channel Single Logout (SLO). The full protocol contract is in the package's `docs/architecture.md`.

### Package Namespace

All classes live under `JeffersonGoncalves\SsoServer`.

### Architecture

- **Service**: `Services\ServerTokenManager` (singleton, also bound to `Contracts\TokenRepositoryContract`) issues/consumes codes, signs and validates JWTs, manages keys/JWKS, and runs `logoutUser()`. Facade: `Facades\SsoServer`.
- **Models**: `Models\SsoClient` (`client_id`, `client_secret` with the `encrypted` cast, `redirect_uri`, `slo_webhook_url`, `is_active`) and `Models\SsoActiveSession` (one row per issued token, used for revocation and SLO).
- **Controllers** (routes in `routes/web.php`, prefix `sso-server.routes.prefix`, default `sso`):
  - `GET /sso/authorize` — `web` + `auth:{guard}`; PKCE `S256` only, `state` required, exact `redirect_uri` match.
  - `POST /sso/token` — exchanges the one-time code (`grant_type=authorization_code`).
  - `GET /sso/userinfo` — Bearer token; response signed with `X-SSO-Timestamp` / `X-SSO-Signature`.
  - `GET /sso/logout` — client-initiated logout; requires a `token_hint` issued to that client.
  - `GET /.well-known/jwks.json` — not prefixed.
- **Job**: `Jobs\DispatchSingleLogoutJob` POSTs the signed SLO webhook (5 tries, backoff 10/30/60/300s).
- **Events**: `Events\ClientAuthorizedEvent`, `Events\UserLoggedOutEvent`.
- **Commands**: `sso-server:keys`, `sso-server:client`, `sso-server:prune`.

### Key Conventions

- Authorization codes live 60s (`code_ttl`), are cached by SHA-256 hash, and are burned on the first exchange attempt through an atomic `Cache::add()`. Use a cache store with atomic `add()` (redis, memcached, database).
- Keys are files in `sso-server.keys.path` (default `storage/sso-server`) named `{kid}.key` / `{kid}.pub`, `kid` = `YmdHis-random6`; the highest `kid` signs. In multi-server setups this directory must be shared.
- HMAC signatures are `hash_hmac('sha256', "{timestamp}.{raw body}", client_secret)`. The secret is stored encrypted (not hashed) so the server can sign.
- A token is only accepted by `/sso/userinfo` while its `sso_active_sessions` row exists; logging out deletes the rows.
- `Illuminate\Auth\Events\Logout` on the configured guard (`sso-server.guard`) triggers SLO to every active client of that user that has a `slo_webhook_url`.
- The default serializer emits `name`, `email` and `email_verified`. Reserved JWT claims (`iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`) always come from the server; `sub` is always a string.

### Custom claims

@verbatim
<code-snippet name="Custom user serializer" lang="php">
use Illuminate\Contracts\Auth\Authenticatable;
use JeffersonGoncalves\SsoServer\Contracts\SsoUserSerializerContract;
use JeffersonGoncalves\SsoServer\Models\SsoClient;

class TenantUserSerializer implements SsoUserSerializerContract
{
    public function serialize(Authenticatable $user, SsoClient $client): array
    {
        return [
            'name' => $user->name,
            'email' => $user->email,
            // Keep this claim: clients rely on it before linking accounts by email.
            'email_verified' => $user->hasVerifiedEmail(),
            'tenant_id' => $user->tenant_id,
        ];
    }
}

// config/sso-server.php
'serializer' => TenantUserSerializer::class,
</code-snippet>
@endverbatim

### Security rules

- Never log, dump or return `client_secret` (it is `$hidden` on the model; keep it that way).
- Never relax `redirect_uri` matching (no wildcards, prefixes or regex) and never redirect authorize errors back to the client: they stay an HTTP 400 on the server.
- Never accept `code_challenge_method=plain` or make `state` optional.
- Keep `email_verified` in custom serializers and never default it to `true`.
- Do not bypass `ServerTokenManager` to mint tokens; every token needs its `sso_active_sessions` row or revocation and SLO break.
