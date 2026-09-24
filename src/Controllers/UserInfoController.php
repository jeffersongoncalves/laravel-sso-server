<?php

namespace JeffersonGoncalves\SsoServer\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use JeffersonGoncalves\SsoServer\Models\SsoClient;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

/**
 * GET /sso/userinfo — fresh claims for a Bearer token. The body is signed
 * with the client secret (X-SSO-Signature) so clients that validate via this
 * synchronous call, instead of JWKS, can trust the response.
 */
class UserInfoController extends Controller
{
    public function __invoke(Request $request, ServerTokenManager $tokens): Response|JsonResponse
    {
        $claims = $tokens->validateAccessToken((string) $request->bearerToken());
        $client = $claims ? SsoClient::findActive((string) $claims['aud']) : null;
        $user = $client ? $tokens->userProvider()->retrieveById($claims['sub']) : null;

        if ($user === null) {
            return response()
                ->json(['error' => 'invalid_token'], 401)
                ->header('WWW-Authenticate', 'Bearer error="invalid_token"');
        }

        $body = (string) json_encode(array_merge(
            $tokens->serializer()->serialize($user, $client),
            ['sub' => $claims['sub']],
        ));

        return response($body, 200, array_merge(
            ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'],
            ServerTokenManager::signatureHeaders($body, $client->client_secret),
        ));
    }
}
