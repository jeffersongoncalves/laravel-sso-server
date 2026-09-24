<?php

namespace JeffersonGoncalves\SsoServer\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \JeffersonGoncalves\SsoServer\SsoServer
 */
class SsoServer extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'laravel-sso-server';
    }
}
