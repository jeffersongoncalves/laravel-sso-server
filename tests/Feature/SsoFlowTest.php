<?php

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use JeffersonGoncalves\SsoServer\Events\ClientAuthorizedEvent;
use JeffersonGoncalves\SsoServer\Events\UserLoggedOutEvent;
use JeffersonGoncalves\SsoServer\Jobs\DispatchSingleLogoutJob;
use JeffersonGoncalves\SsoServer\Models\SsoActiveSession;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0123456789';

function challenge(string $verifier = VERIFIER): string
{
    return ServerTokenManager::base64UrlEncode(hash('sha256', $verifier, true));
}

function authorizeQuery($client, array $overrides = []): string
{
    return '/sso/authorize?'.http_build_query(array_merge([
        'client_id' => $client->client_id,
        'redirect_uri' => $client->redirect_uri,
        'state' => 'state-0123456789abcdef',
        'code_challenge' => challenge(),
        'code_challenge_method' => 'S256',
    ], $overrides));
}

function obtainCode($test, $client, $user): string
{
    $location = $test->actingAs($user)->get(authorizeQuery($client))->assertRedirect()->headers->get('Location');
    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

    return $query['code'];
}

function exchange($test, $client, string $code, array $overrides = [])
{
    return $test->postJson('/sso/token', array_merge([
        'grant_type' => 'authorization_code',
        'client_id' => $client->client_id,
        'client_secret' => $client->client_secret,
        'code' => $code,
        'redirect_uri' => $client->redirect_uri,
        'code_verifier' => VERIFIER,
    ], $overrides));
}

it('issues a code and echoes state to the registered redirect uri', function () {
    Event::fake([ClientAuthorizedEvent::class]);
    $client = $this->makeClient();

    $location = $this->actingAs($this->makeUser())->get(authorizeQuery($client))->assertRedirect()->headers->get('Location');

    expect($location)->toStartWith('https://client.test/sso/callback?code=')->toContain('state=state-0123456789abcdef');
    Event::assertDispatched(ClientAuthorizedEvent::class);
});

it('refuses mismatched redirect uri, inactive clients and missing pkce', function () {
    $user = $this->makeUser();
    $client = $this->makeClient();

    $this->actingAs($user)->get(authorizeQuery($client, ['redirect_uri' => 'https://evil.test/cb']))->assertStatus(400);
    $this->actingAs($user)->get(authorizeQuery($client, ['code_challenge_method' => 'plain']))->assertStatus(400);
    $this->actingAs($user)->get(authorizeQuery($this->makeClient(['is_active' => false])))->assertStatus(400);
});

it('exchanges a code for an RS256 token verifiable with the JWKS', function () {
    $client = $this->makeClient();
    $user = $this->makeUser();

    $response = exchange($this, $client, obtainCode($this, $client, $user))
        ->assertOk()
        ->assertJsonPath('token_type', 'Bearer');

    [$header, $payload, $signature] = explode('.', $response->json('access_token'));
    $claims = json_decode(ServerTokenManager::base64UrlDecode($payload), true);
    $kid = json_decode(ServerTokenManager::base64UrlDecode($header), true)['kid'];

    expect($claims)->toMatchArray(['sub' => (string) $user->id, 'aud' => $client->client_id, 'iss' => 'https://idp.test', 'email' => $user->email]);

    $jwk = collect($this->getJson('/.well-known/jwks.json')->assertOk()->json('keys'))->firstWhere('kid', $kid);
    expect($jwk)->toMatchArray(['kty' => 'RSA', 'alg' => 'RS256']);

    $pem = (string) file_get_contents(config('sso-server.keys.path')."/{$kid}.pub");
    expect(openssl_verify("{$header}.{$payload}", ServerTokenManager::base64UrlDecode($signature), $pem, OPENSSL_ALGO_SHA256))->toBe(1);

    expect(SsoActiveSession::where('user_id', (string) $user->id)->count())->toBe(1);
});

it('rejects replayed codes, wrong verifiers, wrong secrets and codes of other clients', function () {
    $client = $this->makeClient();
    $other = $this->makeClient();
    $user = $this->makeUser();

    $code = obtainCode($this, $client, $user);
    exchange($this, $client, $code)->assertOk();
    exchange($this, $client, $code)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    exchange($this, $client, obtainCode($this, $client, $user), ['code_verifier' => str_repeat('a', 43)])->assertStatus(400);
    exchange($this, $client, obtainCode($this, $client, $user), ['client_secret' => 'nope'])->assertStatus(401);
    exchange($this, $other, obtainCode($this, $client, $user), ['redirect_uri' => $client->redirect_uri])->assertStatus(400);
});

it('serves signed userinfo and revokes it on logout', function () {
    Queue::fake();
    $client = $this->makeClient();
    $user = $this->makeUser();
    $token = exchange($this, $client, obtainCode($this, $client, $user))->json('access_token');

    $response = $this->withToken($token)->get('/sso/userinfo')->assertOk()->assertJsonPath('sub', (string) $user->id);

    $expected = ServerTokenManager::signatureHeaders($response->getContent(), $client->client_secret, (int) $response->headers->get('X-SSO-Timestamp'));
    expect($response->headers->get('X-SSO-Signature'))->toBe($expected['X-SSO-Signature']);

    Auth::guard('web')->login($user);
    Auth::guard('web')->logout();

    $this->withToken($token)->get('/sso/userinfo')->assertStatus(401);
    $this->withToken('garbage.token.here')->get('/sso/userinfo')->assertStatus(401);
});

it('dispatches a single logout job per client on native logout', function () {
    Queue::fake();
    Event::fake([UserLoggedOutEvent::class]);
    $a = $this->makeClient();
    $b = $this->makeClient(['slo_webhook_url' => null]);
    $user = $this->makeUser();

    exchange($this, $a, obtainCode($this, $a, $user));
    exchange($this, $a, obtainCode($this, $a, $user));
    exchange($this, $b, obtainCode($this, $b, $user));

    Auth::guard('web')->login($user);
    Auth::guard('web')->logout();

    Queue::assertPushed(DispatchSingleLogoutJob::class, 1);
    Queue::assertPushed(DispatchSingleLogoutJob::class, fn ($job) => $job->client->is($a));
    Event::assertDispatched(UserLoggedOutEvent::class, fn ($e) => $e->clientIds === [$a->client_id, $b->client_id]);
    expect(SsoActiveSession::count())->toBe(0);
});

it('posts a signed logout webhook', function () {
    Http::fake();
    $client = $this->makeClient();

    (new DispatchSingleLogoutJob($client, '42'))->handle();

    Http::assertSent(function ($request) use ($client) {
        $expected = hash_hmac('sha256', $request->header('X-SSO-Timestamp')[0].'.'.$request->body(), $client->client_secret);

        return $request->url() === 'https://client.test/sso/logout'
            && $request['event'] === 'logout'
            && $request['sub'] === '42'
            && hash_equals($expected, $request->header('X-SSO-Signature')[0]);
    });
});

it('rotates keys keeping the previous one in the jwks', function () {
    $this->artisan('sso-server:keys')->assertSuccessful();
    $this->artisan('sso-server:keys')->assertSuccessful();

    expect($this->getJson('/.well-known/jwks.json')->json('keys'))->toHaveCount(2);
});

it('creates clients and prunes expired sessions', function () {
    $this->artisan('sso-server:client', ['name' => 'App', 'redirect_uri' => 'https://app.test/cb'])->assertSuccessful();
    $this->artisan('sso-server:client', ['name' => 'Bad', 'redirect_uri' => 'not-a-url'])->assertFailed();

    $client = $this->makeClient();
    SsoActiveSession::create(['client_id' => $client->id, 'user_id' => '1', 'session_token_hash' => str_repeat('a', 64), 'expires_at' => now()->subDays(2)]);
    SsoActiveSession::create(['client_id' => $client->id, 'user_id' => '1', 'session_token_hash' => str_repeat('b', 64), 'expires_at' => now()->addHour()]);

    $this->artisan('sso-server:prune')->assertSuccessful();

    expect(SsoActiveSession::count())->toBe(1);
});
