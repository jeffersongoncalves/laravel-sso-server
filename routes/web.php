<?php

use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\SsoServer\Controllers\AuthorizeController;
use JeffersonGoncalves\SsoServer\Controllers\JwksController;
use JeffersonGoncalves\SsoServer\Controllers\LogoutController;
use JeffersonGoncalves\SsoServer\Controllers\TokenExchangeController;
use JeffersonGoncalves\SsoServer\Controllers\UserInfoController;

if (! config('sso-server.routes.enabled', true)) {
    return;
}

$api = config('sso-server.routes.api_middleware', []);

Route::prefix(config('sso-server.routes.prefix', 'sso'))->name('sso-server.')->group(function () use ($api) {
    Route::get('authorize', AuthorizeController::class)
        ->middleware([...config('sso-server.routes.authorize_middleware', ['web']), 'auth:'.config('sso-server.guard', 'web')])
        ->name('authorize');

    // No "auth": the user may already be logged out of the IdP.
    Route::get('logout', LogoutController::class)
        ->middleware(config('sso-server.routes.authorize_middleware', ['web']))
        ->name('logout');

    Route::post('token', TokenExchangeController::class)->middleware($api)->name('token');
    Route::get('userinfo', UserInfoController::class)->middleware($api)->name('userinfo');
});

Route::get('.well-known/jwks.json', JwksController::class)->middleware($api)->name('sso-server.jwks');
