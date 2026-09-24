<div class="filament-hidden">

![Laravel SSO Server](https://raw.githubusercontent.com/jeffersongoncalves/laravel-sso-server/main/art/jeffersongoncalves-laravel-sso-server.png)

</div>

# Laravel SSO Server

Central SSO identity provider for Laravel: Authorization Code + PKCE, RS256 JWT with JWKS and key rotation, one-time codes, and back-channel Single Logout webhooks.

## Installation

You can install the package via composer:

```bash
composer require jeffersongoncalves/laravel-sso-server
```

Publish and run the migrations, publish the config, then generate the first signing key:

```bash
php artisan vendor:publish --tag="sso-server-migrations"
php artisan migrate
php artisan vendor:publish --tag="sso-server-config"
php artisan sso-server:keys
```

## Usage

### Register a client

```bash
php artisan sso-server:client "Billing" https://billing.test/sso/callback --slo=https://billing.test/sso/logout
```

Prints the `client_id` and `client_secret`. The secret is stored encrypted, since the server needs it to sign responses and webhooks.

### Endpoints

| Method | URI | Purpose |
|--------|-----|---------|
| GET | `/sso/authorize` | Authorization Code + PKCE (`S256` only). Runs behind `auth`, so guests go to your login page first. Requires `client_id`, `redirect_uri` (exact match), `state`, `code_challenge`, `code_challenge_method=S256`. |
| POST | `/sso/token` | Exchanges the one-time code (`grant_type=authorization_code`, `client_id`, `client_secret`, `code`, `redirect_uri`, `code_verifier`) for an RS256 access token. |
| GET | `/sso/userinfo` | Current claims for a `Bearer` token. Signed with `X-SSO-Timestamp` + `X-SSO-Signature`. |
| GET | `/.well-known/jwks.json` | Public keys used to verify access tokens. |

### Security model

- **One-time codes**: stored in cache (hashed) for `code_ttl` seconds (default 60) and consumed with an atomic `Cache::add()`, so a replayed code always fails. Use a cache store with atomic `add()` (redis, memcached, database).
- **Tokens**: RS256 JWTs with a `kid` header. `sso-server:keys` rotates the key and keeps `keys.keep` pairs (default 2), so tokens signed before the rotation still verify.
- **Signatures**: `X-SSO-Signature = hash_hmac('sha256', "{X-SSO-Timestamp}.{raw body}", client_secret)`. Clients should reject stale timestamps.
- **Revocation**: every issued token has an `sso_active_sessions` row. `/sso/userinfo` rejects tokens whose row is gone.

### Single Logout

When the configured guard fires Laravel's `Logout` event, the server deletes the user's active sessions and queues a `DispatchSingleLogoutJob` for each client with a `slo_webhook_url`. The job POSTs a signed JSON body:

```json
{"event": "logout", "sub": "42", "aud": "<client_id>", "iat": 1790000000, "jti": "<uuid>"}
```

You can also trigger it yourself: `SsoServer::logoutUser((string) $user->id)`.

### Custom claims

Implement `SsoUserSerializerContract` and set it in `config/sso-server.php`:

```php
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
            'roles' => $user->getRoleNames(),
            'tenant_id' => $user->tenant_id,
        ];
    }
}
```

Reserved claims (`iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`) are always set by the server.

### Maintenance

```bash
php artisan sso-server:prune   # delete sessions expired more than 24h ago (--hours=N)
php artisan sso-server:keys    # rotate the signing key
```

On Windows, if key generation fails with an OpenSSL error, point `SSO_SERVER_OPENSSL_CONF` at an `openssl.cnf`.

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [jeffersongoncalves](https://github.com/jeffersongoncalves)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
