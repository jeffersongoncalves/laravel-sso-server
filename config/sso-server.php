<?php

use JeffersonGoncalves\SsoServer\Services\DefaultUserSerializer;

return [

    /*
    | "iss" claim of issued tokens. Null falls back to config('app.url').
    */
    'issuer' => env('SSO_SERVER_ISSUER'),

    /*
    | Guard whose users authenticate on the server. Its user provider resolves
    | the "sub" claim, and only its Logout events trigger Single Logout.
    */
    'guard' => env('SSO_SERVER_GUARD', 'web'),

    'tables' => [
        'clients' => 'sso_clients',
        'active_sessions' => 'sso_active_sessions',
    ],

    'routes' => [
        'enabled' => true,
        'prefix' => 'sso',
        // "auth:{guard}" is appended automatically.
        'authorize_middleware' => ['web'],
        'api_middleware' => ['throttle:60,1'],
    ],

    /*
    | Authorization codes are one-time use and short lived (30-60s).
    */
    'code_ttl' => 60,

    /*
    | Access token lifetime in seconds. Also the lifetime of the active session
    | row tracked for Single Logout.
    */
    'token_ttl' => 3600,

    /*
    | Cache store for authorization codes. Must support atomic add() (redis,
    | memcached, database, array). Null uses the default store.
    */
    'cache_store' => env('SSO_SERVER_CACHE_STORE'),

    'keys' => [
        // RS256 key pairs: {kid}.key (private) + {kid}.pub (public).
        'path' => storage_path('sso-server'),
        // Pairs kept after rotation. Keep >= 2 so tokens signed by the
        // previous key still verify until they expire.
        'keep' => 2,
        // Path to openssl.cnf, only needed where PHP has none (common on Windows).
        'openssl_config' => env('SSO_SERVER_OPENSSL_CONF'),
    ],

    'serializer' => DefaultUserSerializer::class,

    'slo' => [
        'connection' => env('SSO_SERVER_SLO_CONNECTION'),
        'queue' => env('SSO_SERVER_SLO_QUEUE'),
        'timeout' => 10,
    ],

];
