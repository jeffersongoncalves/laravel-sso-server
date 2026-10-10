<?php

use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;
use JeffersonGoncalves\SsoServer\Tests\TestCase;

uses(TestCase::class)->in('Feature');

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

function logoutQuery($client, string $token, array $overrides = []): string
{
    return '/sso/logout?'.http_build_query(array_merge([
        'client_id' => $client->client_id,
        'token_hint' => $token,
        'post_logout_redirect_uri' => 'https://client.test/bye',
        'state' => 'st-123',
    ], $overrides));
}
