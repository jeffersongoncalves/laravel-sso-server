<?php

namespace JeffersonGoncalves\SsoServer\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use JeffersonGoncalves\SsoServer\Models\SsoClient;

interface TokenRepositoryContract
{
    public function issueCode(SsoClient $client, Authenticatable $user, string $codeChallenge, string $redirectUri): string;

    /**
     * One-time: the first call wins, every later call returns null.
     *
     * @return array{client_id: int, user_id: string, code_challenge: string, redirect_uri: string}|null
     */
    public function consumeCode(string $code): ?array;

    /**
     * @return array{access_token: string, token_type: string, expires_in: int}
     */
    public function issueAccessToken(SsoClient $client, Authenticatable $user): array;

    /**
     * Claims of a valid, unexpired, not logged-out token, or null.
     *
     * @return array<string, mixed>|null
     */
    public function validateAccessToken(string $token): ?array;
}
