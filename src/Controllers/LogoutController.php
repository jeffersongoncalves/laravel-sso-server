<?php

namespace JeffersonGoncalves\SsoServer\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use JeffersonGoncalves\SsoServer\Models\SsoClient;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

/**
 * GET /sso/logout — client-initiated (RP-initiated) federated logout, reached
 * through a browser redirect so the IdP's own session cookie is present.
 *
 * token_hint must be an access token this server issued to the calling
 * client (expired is fine). That limits a client to logging out users it
 * actually signed in, instead of any user id it can name.
 */
class LogoutController extends Controller
{
    public function __invoke(Request $request, ServerTokenManager $tokens): RedirectResponse
    {
        $validator = Validator::make($request->query(), [
            'client_id' => ['required', 'string'],
            'token_hint' => ['required', 'string'],
            'post_logout_redirect_uri' => ['sometimes', 'string', 'url'],
            'state' => ['sometimes', 'string', 'max:255'],
        ]);

        abort_if($validator->fails(), 400, 'invalid_request: '.$validator->errors()->first());

        $data = $validator->validated();
        $client = SsoClient::findActive($data['client_id']);
        $claims = $client ? $tokens->verifiedClaims($data['token_hint']) : null;

        abort_if($claims === null || ($claims['aud'] ?? null) !== $client->client_id, 400, 'invalid_token_hint');

        $redirect = $data['post_logout_redirect_uri'] ?? null;

        // Same origin as the registered redirect_uri: no open redirect, no new column.
        abort_if($redirect !== null && ! self::sameOrigin($redirect, $client->redirect_uri), 400, 'invalid_post_logout_redirect_uri');

        $sub = (string) $claims['sub'];

        // Revoke first, sparing the initiator's webhook; the guard logout below
        // then fires Logout, whose listener finds nothing left to revoke.
        $tokens->logoutUser($sub, $client);

        $guard = Auth::guard(config('sso-server.guard', 'web'));

        // Never log out a different person who happens to share this browser.
        if ((string) $guard->id() === $sub) {
            $guard->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        if ($redirect === null) {
            return redirect('/');
        }

        $query = isset($data['state']) ? (str_contains($redirect, '?') ? '&' : '?').http_build_query(['state' => $data['state']]) : '';

        return redirect()->away($redirect.$query);
    }

    protected static function sameOrigin(string $a, string $b): bool
    {
        $origin = fn (string $url) => [
            strtolower((string) parse_url($url, PHP_URL_SCHEME)),
            strtolower((string) parse_url($url, PHP_URL_HOST)),
            parse_url($url, PHP_URL_PORT),
        ];

        return $origin($a) === $origin($b);
    }
}
