<?php

namespace JeffersonGoncalves\SsoServer\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

/**
 * GET /.well-known/jwks.json — every retained public key, so tokens signed
 * before a rotation keep verifying until they expire.
 */
class JwksController extends Controller
{
    public function __invoke(ServerTokenManager $tokens): JsonResponse
    {
        return response()
            ->json($tokens->jwks())
            ->header('Cache-Control', 'public, max-age=300');
    }
}
