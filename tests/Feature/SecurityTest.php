<?php

use Illuminate\Auth\Events\Logout;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\SsoServer\Jobs\DispatchSingleLogoutJob;
use JeffersonGoncalves\SsoServer\Models\SsoActiveSession;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

/** Re-encodes a token with header/claim overrides, keeping the original signature unless given. */
function forge(string $token, array $header = [], array $claims = [], ?string $signature = null): string
{
    [$h, $p, $s] = explode('.', $token);
    $encode = fn (string $part, array $extra) => ServerTokenManager::base64UrlEncode((string) json_encode(
        array_merge(json_decode(ServerTokenManager::base64UrlDecode($part), true), $extra)
    ));

    return $encode($h, $header).'.'.$encode($p, $claims).'.'.($signature ?? $s);
}

function issueToken($test, $client, $user): string
{
    return exchange($test, $client, obtainCode($test, $client, $user))->assertOk()->json('access_token');
}

it('rejects tampered, unsigned and foreign-key tokens', function () {
    $client = $this->makeClient();
    $user = $this->makeUser();
    $token = issueToken($this, $client, $user);
    $tokens = app(ServerTokenManager::class);

    expect($tokens->verifiedClaims($token))->not->toBeNull();

    $forged = [
        'swapped sub' => forge($token, claims: ['sub' => (string) $this->makeUser()->id]),
        'alg none' => forge($token, header: ['alg' => 'none'], signature: ''),
        'alg confusion' => forge($token, header: ['alg' => 'HS256'], signature: ServerTokenManager::base64UrlEncode(hash_hmac('sha256', 'x', 'y', true))),
        'path traversal kid' => forge($token, header: ['kid' => '../../../../etc/passwd']),
        'unknown kid' => forge($token, header: ['kid' => 'missing']),
        'two parts' => implode('.', array_slice(explode('.', $token), 0, 2)),
    ];

    foreach ($forged as $case => $bad) {
        expect($tokens->verifiedClaims($bad))->toBeNull($case);
        $this->withToken($bad)->get('/sso/userinfo')->assertStatus(401);
    }
});

it('rejects tokens from another issuer', function () {
    $token = issueToken($this, $this->makeClient(), $this->makeUser());

    config(['app.url' => 'https://other-idp.test']);

    expect(app(ServerTokenManager::class)->verifiedClaims($token))->toBeNull();
    $this->withToken($token)->get('/sso/userinfo')->assertStatus(401);
});

it('rejects expired access tokens', function () {
    $token = issueToken($this, $this->makeClient(), $this->makeUser());

    $this->withToken($token)->get('/sso/userinfo')->assertOk();

    $this->travel(config('sso-server.token_ttl') + 1)->seconds();

    $this->withToken($token)->get('/sso/userinfo')->assertStatus(401);
});

it('rejects tokens of a client deactivated after issuance', function () {
    $client = $this->makeClient();
    $token = issueToken($this, $client, $this->makeUser());

    $client->update(['is_active' => false]);

    $this->withToken($token)->get('/sso/userinfo')->assertStatus(401);
});

it('rejects expired authorization codes', function () {
    $client = $this->makeClient();
    $code = obtainCode($this, $client, $this->makeUser());

    $this->travel(config('sso-server.code_ttl') + 1)->seconds();

    exchange($this, $client, $code)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('burns the code on any exchange attempt, even a failed one', function () {
    $client = $this->makeClient();
    $user = $this->makeUser();

    $code = obtainCode($this, $client, $user);
    exchange($this, $client, $code, ['client_secret' => 'nope'])->assertStatus(401);
    exchange($this, $client, $code)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    $code = obtainCode($this, $client, $user);
    exchange($this, $client, $code, ['redirect_uri' => 'https://client.test/other'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    exchange($this, $client, $code)->assertStatus(400);

    expect(SsoActiveSession::count())->toBe(0);
});

it('refuses codes of users deleted before the exchange', function () {
    $client = $this->makeClient();
    $user = $this->makeUser();
    $code = obtainCode($this, $client, $user);

    $user->delete();

    exchange($this, $client, $code)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('requires an authenticated user to authorize', function () {
    $this->getJson(authorizeQuery($this->makeClient()))->assertUnauthorized();
});

it('appends code and state to a redirect uri that has a query string', function () {
    $client = $this->makeClient(['redirect_uri' => 'https://client.test/cb?tenant=1']);

    $location = $this->actingAs($this->makeUser())->get(authorizeQuery($client))->assertRedirect()->headers->get('Location');

    expect($location)->toStartWith('https://client.test/cb?tenant=1&code=');
});

it('only accepts post logout redirects on the exact client origin', function () {
    $client = $this->makeClient();
    $token = issueToken($this, $client, $this->makeUser());

    foreach (['http://client.test/bye', 'https://client.test:8443/bye', 'https://client.test.evil.test/bye', 'https://evil.test/?https://client.test'] as $redirect) {
        $this->get(logoutQuery($client, $token, ['post_logout_redirect_uri' => $redirect]))->assertStatus(400);
    }

    expect(SsoActiveSession::count())->toBe(1);
});

it('ignores logouts from other guards', function () {
    $client = $this->makeClient();
    $user = $this->makeUser();
    issueToken($this, $client, $user);

    event(new Logout('admin', $user));

    expect(SsoActiveSession::count())->toBe(1);
});

it('signs with the newest key even when rotated within the same second', function () {
    $tokens = app(ServerTokenManager::class);

    foreach (range(1, 5) as $_) {
        $kid = $tokens->generateKeyPair(2);
        $kids = collect($tokens->jwks()['keys'])->pluck('kid');

        expect($kids)->toHaveCount(2)->and($kids->last())->toBe($kid);
    }

    $token = issueToken($this, $this->makeClient(), $this->makeUser());
    $header = json_decode(ServerTokenManager::base64UrlDecode(explode('.', $token)[0]), true);

    expect($header['kid'])->toBe($kid);
});

it('keeps tokens of the previous key valid until that key is pruned', function () {
    $token = issueToken($this, $this->makeClient(), $this->makeUser());

    $this->artisan('sso-server:keys', ['--keep' => 2])->assertSuccessful();
    $this->withToken($token)->get('/sso/userinfo')->assertOk();

    $this->artisan('sso-server:keys', ['--keep' => 2])->assertSuccessful();
    $this->withToken($token)->get('/sso/userinfo')->assertStatus(401);
});

it('skips the webhook for deactivated clients', function () {
    Http::fake();
    $client = $this->makeClient(['is_active' => false]);

    (new DispatchSingleLogoutJob($client, '42'))->handle();

    Http::assertNothingSent();
});

it('throws on a failed webhook so the job retries', function () {
    Http::fake(['*' => Http::response('down', 503)]);

    (new DispatchSingleLogoutJob($this->makeClient(), '42'))->handle();
})->throws(RequestException::class);
