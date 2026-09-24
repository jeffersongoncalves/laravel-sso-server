<?php

namespace JeffersonGoncalves\SsoServer\Facades;

use Illuminate\Support\Facades\Facade;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

/**
 * @method static void logoutUser(string $userId)
 * @method static array|null validateAccessToken(string $token)
 * @method static string generateKeyPair(?int $keep = null)
 * @method static array jwks()
 *
 * @see ServerTokenManager
 */
class SsoServer extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return ServerTokenManager::class;
    }
}
