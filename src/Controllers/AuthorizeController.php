<?php

namespace JeffersonGoncalves\SsoServer\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Validator;
use JeffersonGoncalves\SsoServer\Contracts\TokenRepositoryContract;
use JeffersonGoncalves\SsoServer\Events\ClientAuthorizedEvent;
use JeffersonGoncalves\SsoServer\Models\SsoClient;

/**
 * GET /sso/authorize — runs behind "auth", so the user is already logged in
 * on the server (the login page redirects back here as the intended URL).
 */
class AuthorizeController extends Controller
{
    public function __invoke(Request $request, TokenRepositoryContract $tokens): RedirectResponse
    {
        $validator = Validator::make($request->query(), [
            'response_type' => ['sometimes', 'in:code'],
            'client_id' => ['required', 'string'],
            'redirect_uri' => ['required', 'string'],
            'state' => ['required', 'string', 'min:16', 'max:255'],
            // base64url(sha256(verifier)) is always 43 chars.
            'code_challenge' => ['required', 'string', 'size:43', 'regex:/^[A-Za-z0-9_-]+$/'],
            'code_challenge_method' => ['required', 'in:S256'],
        ]);

        abort_if($validator->fails(), 400, 'invalid_request: '.$validator->errors()->first());

        $data = $validator->validated();
        $client = SsoClient::findActive($data['client_id']);

        // Never redirect to an unverified URI (open redirect / code leak): fail here instead.
        abort_if($client === null, 400, 'invalid_client');
        abort_unless(hash_equals($client->redirect_uri, $data['redirect_uri']), 400, 'invalid_redirect_uri');

        $user = $request->user();

        $code = $tokens->issueCode($client, $user, $data['code_challenge'], $data['redirect_uri']);

        event(new ClientAuthorizedEvent($client, $user));

        $separator = str_contains($client->redirect_uri, '?') ? '&' : '?';

        return redirect()->away($client->redirect_uri.$separator.http_build_query([
            'code' => $code,
            'state' => $data['state'],
        ]));
    }
}
