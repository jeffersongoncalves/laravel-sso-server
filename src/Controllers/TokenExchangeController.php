<?php

namespace JeffersonGoncalves\SsoServer\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Validator;
use JeffersonGoncalves\SsoServer\Models\SsoClient;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

/**
 * POST /sso/token — server-to-server exchange of a one-time code for an
 * RS256 access token. Authenticates the client and verifies PKCE.
 */
class TokenExchangeController extends Controller
{
    public function __invoke(Request $request, ServerTokenManager $tokens): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'grant_type' => ['required', 'in:authorization_code'],
            'client_id' => ['required', 'string'],
            'client_secret' => ['required', 'string'],
            'code' => ['required', 'string'],
            'redirect_uri' => ['required', 'string'],
            'code_verifier' => ['required', 'string', 'min:43', 'max:128'],
        ]);

        if ($validator->fails()) {
            return $this->error('invalid_request', $validator->errors()->first());
        }

        $data = $validator->validated();

        // Burn the code first: any exchange attempt, valid or not, uses it up.
        $payload = $tokens->consumeCode($data['code']);

        $client = SsoClient::findActive($data['client_id']);

        if ($client === null || ! $client->secretMatches($data['client_secret'])) {
            return $this->error('invalid_client', 'Client authentication failed.', 401);
        }

        if ($payload === null
            || $payload['client_id'] !== $client->id
            || ! hash_equals($payload['redirect_uri'], $data['redirect_uri'])
            || ! ServerTokenManager::verifyPkce($data['code_verifier'], $payload['code_challenge'])) {
            return $this->error('invalid_grant', 'The authorization code is invalid, expired or already used.');
        }

        $user = $tokens->userProvider()->retrieveById($payload['user_id']);

        if ($user === null) {
            return $this->error('invalid_grant', 'The user no longer exists.');
        }

        return response()
            ->json($tokens->issueAccessToken($client, $user))
            ->header('Cache-Control', 'no-store')
            ->header('Pragma', 'no-cache');
    }

    protected function error(string $error, string $description, int $status = 400): JsonResponse
    {
        return response()->json(['error' => $error, 'error_description' => $description], $status);
    }
}
