<?php

namespace JeffersonGoncalves\SsoServer\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use JeffersonGoncalves\SsoServer\Contracts\SsoUserSerializerContract;
use JeffersonGoncalves\SsoServer\Contracts\TokenRepositoryContract;
use JeffersonGoncalves\SsoServer\Events\UserLoggedOutEvent;
use JeffersonGoncalves\SsoServer\Jobs\DispatchSingleLogoutJob;
use JeffersonGoncalves\SsoServer\Models\SsoActiveSession;
use JeffersonGoncalves\SsoServer\Models\SsoClient;
use RuntimeException;

class ServerTokenManager implements TokenRepositoryContract
{
    public function __construct(protected SsoUserSerializerContract $serializer) {}

    // --- Authorization codes -------------------------------------------------

    public function issueCode(SsoClient $client, Authenticatable $user, string $codeChallenge, string $redirectUri): string
    {
        $code = Str::random(64);

        $this->cache()->put($this->codeKey($code), [
            'client_id' => $client->id,
            'user_id' => (string) $user->getAuthIdentifier(),
            'code_challenge' => $codeChallenge,
            'redirect_uri' => $redirectUri,
        ], $this->codeTtl());

        return $code;
    }

    public function consumeCode(string $code): ?array
    {
        $key = $this->codeKey($code);

        // add() is atomic (only one caller creates the marker), so two concurrent
        // exchanges of the same code can never both succeed.
        if (! $this->cache()->add($key.':used', true, $this->codeTtl())) {
            return null;
        }

        return $this->cache()->pull($key);
    }

    public static function verifyPkce(string $verifier, string $challenge): bool
    {
        return hash_equals($challenge, self::base64UrlEncode(hash('sha256', $verifier, true)));
    }

    // --- Access tokens (RS256 JWT) -------------------------------------------

    public function issueAccessToken(SsoClient $client, Authenticatable $user): array
    {
        $now = time();
        $ttl = (int) config('sso-server.token_ttl', 3600);

        $claims = array_merge($this->serializer->serialize($user, $client), [
            'iss' => $this->issuer(),
            'sub' => (string) $user->getAuthIdentifier(),
            'aud' => $client->client_id,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $ttl,
            'jti' => (string) Str::uuid(),
        ]);

        [$kid, $privateKey] = $this->currentKey();

        $token = $this->encodeJwt($claims, $kid, $privateKey);

        SsoActiveSession::create([
            'client_id' => $client->id,
            'user_id' => $claims['sub'],
            'session_token_hash' => hash('sha256', $token),
            'expires_at' => $claims['exp'],
        ]);

        return ['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => $ttl];
    }

    public function validateAccessToken(string $token): ?array
    {
        $claims = $this->verifiedClaims($token);

        if ($claims === null || ($claims['exp'] ?? 0) < time()) {
            return null;
        }

        // Signature alone is not enough: the session row disappears on logout.
        $alive = SsoActiveSession::query()
            ->where('session_token_hash', hash('sha256', $token))
            ->where('expires_at', '>', now())
            ->exists();

        return $alive ? $claims : null;
    }

    /**
     * Claims of a token this server signed (RS256, known kid, our issuer),
     * ignoring expiry and revocation. Only for proving who a token was issued
     * to, e.g. a logout hint; use validateAccessToken() to authorize access.
     *
     * @return array<string, mixed>|null
     */
    public function verifiedClaims(string $token): ?array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        $header = json_decode(self::base64UrlDecode($parts[0]), true);
        $claims = json_decode(self::base64UrlDecode($parts[1]), true);

        if (! is_array($header) || ! is_array($claims) || ($header['alg'] ?? null) !== 'RS256') {
            return null;
        }

        $publicKey = $this->publicKey((string) ($header['kid'] ?? ''));

        if ($publicKey === null || openssl_verify($parts[0].'.'.$parts[1], self::base64UrlDecode($parts[2]), $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            return null;
        }

        return ($claims['iss'] ?? null) === $this->issuer() ? $claims : null;
    }

    // --- Users & Single Logout -----------------------------------------------

    public function userProvider(): UserProvider
    {
        return Auth::createUserProvider(config('auth.guards.'.config('sso-server.guard', 'web').'.provider'));
    }

    public function serializer(): SsoUserSerializerContract
    {
        return $this->serializer;
    }

    /**
     * Revokes every session of the user and notifies each client through a
     * signed back-channel webhook. Expired rows are included on purpose: a
     * client's local session can outlive the access token. $initiator (the
     * client that asked for the logout) has its sessions revoked but gets no
     * webhook: it already logged the user out locally.
     */
    public function logoutUser(string $userId, ?SsoClient $initiator = null): void
    {
        $sessions = SsoActiveSession::query()->with('client')->where('user_id', $userId)->get();

        if ($sessions->isEmpty()) {
            return;
        }

        SsoActiveSession::query()->where('user_id', $userId)->delete();

        $clients = $sessions->pluck('client')->filter()->unique('id');

        $clients
            ->filter(fn (SsoClient $client) => $client->is_active && filled($client->slo_webhook_url) && ! $client->is($initiator))
            ->each(fn (SsoClient $client) => DispatchSingleLogoutJob::dispatch($client, $userId));

        event(new UserLoggedOutEvent($userId, $clients->pluck('client_id')->values()->all()));
    }

    /**
     * Headers for an HMAC-SHA256 signed payload. The timestamp is part of the
     * signed string so a captured request cannot be replayed later.
     *
     * @return array{X-SSO-Timestamp: string, X-SSO-Signature: string}
     */
    public static function signatureHeaders(string $body, string $secret, ?int $timestamp = null): array
    {
        $timestamp = (string) ($timestamp ?? time());

        return [
            'X-SSO-Timestamp' => $timestamp,
            'X-SSO-Signature' => hash_hmac('sha256', $timestamp.'.'.$body, $secret),
        ];
    }

    // --- Keys (RS256 + JWKS) -------------------------------------------------

    /**
     * Creates a new key pair, which becomes the signing key, and drops pairs
     * beyond `sso-server.keys.keep`. Returns the new kid.
     */
    public function generateKeyPair(?int $keep = null): string
    {
        $path = $this->keysPath();

        if (! is_dir($path)) {
            mkdir($path, 0700, true);
        }

        // Windows PHP builds often ship without a default openssl.cnf.
        $options = array_filter(['config' => config('sso-server.keys.openssl_config')]);

        $key = openssl_pkey_new($options + ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($key === false || ! openssl_pkey_export($key, $private, null, $options)) {
            throw new RuntimeException('Unable to generate RSA key pair: '.openssl_error_string());
        }

        $details = openssl_pkey_get_details($key);
        $kid = now()->format('YmdHis').'-'.Str::lower(Str::random(6));

        file_put_contents("{$path}/{$kid}.key", $private);
        chmod("{$path}/{$kid}.key", 0600);
        file_put_contents("{$path}/{$kid}.pub", $details['key']);

        $keep = max(1, $keep ?? (int) config('sso-server.keys.keep', 2));

        foreach (array_slice(array_reverse($this->kids()), $keep) as $old) {
            @unlink("{$path}/{$old}.key");
            @unlink("{$path}/{$old}.pub");
        }

        return $kid;
    }

    /** @return array{keys: list<array<string, string>>} */
    public function jwks(): array
    {
        $keys = [];

        foreach ($this->kids() as $kid) {
            $details = openssl_pkey_get_details(openssl_pkey_get_public((string) file_get_contents($this->keysPath()."/{$kid}.pub")));

            $keys[] = [
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => $kid,
                'n' => self::base64UrlEncode($details['rsa']['n']),
                'e' => self::base64UrlEncode($details['rsa']['e']),
            ];
        }

        return ['keys' => $keys];
    }

    /** @return list<string> kids sorted oldest first */
    protected function kids(): array
    {
        $kids = array_map(fn (string $file) => basename($file, '.pub'), glob($this->keysPath().'/*.pub') ?: []);
        sort($kids);

        return $kids;
    }

    /** @return array{0: string, 1: string} */
    protected function currentKey(): array
    {
        $kid = last($this->kids());

        if (! $kid || ! is_file($this->keysPath()."/{$kid}.key")) {
            throw new RuntimeException('No SSO signing key found. Run `php artisan sso-server:keys`.');
        }

        return [$kid, (string) file_get_contents($this->keysPath()."/{$kid}.key")];
    }

    protected function publicKey(string $kid): ?string
    {
        // kid comes from an untrusted header: never let it walk the filesystem.
        if (! in_array($kid, $this->kids(), true)) {
            return null;
        }

        return (string) file_get_contents($this->keysPath()."/{$kid}.pub");
    }

    protected function keysPath(): string
    {
        return rtrim(config('sso-server.keys.path', storage_path('sso-server')), '/\\');
    }

    // --- Helpers -------------------------------------------------------------

    /** @param array<string, mixed> $claims */
    protected function encodeJwt(array $claims, string $kid, string $privateKey): string
    {
        $input = self::base64UrlEncode((string) json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid]))
            .'.'.self::base64UrlEncode((string) json_encode($claims));

        if (! openssl_sign($input, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Unable to sign SSO token: '.openssl_error_string());
        }

        return $input.'.'.self::base64UrlEncode($signature);
    }

    public function issuer(): string
    {
        return (string) (config('sso-server.issuer') ?: config('app.url'));
    }

    protected function cache(): Repository
    {
        return Cache::store(config('sso-server.cache_store'));
    }

    protected function codeKey(string $code): string
    {
        // Hashed so plaintext codes never sit in the cache backend.
        return 'sso-server:code:'.hash('sha256', $code);
    }

    protected function codeTtl(): int
    {
        return (int) config('sso-server.code_ttl', 60);
    }

    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $data): string
    {
        return (string) base64_decode(strtr($data, '-_', '+/'), true);
    }
}
