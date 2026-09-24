<?php

namespace JeffersonGoncalves\SsoServer\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use JeffersonGoncalves\SsoServer\Contracts\SsoUserSerializerContract;
use JeffersonGoncalves\SsoServer\Models\SsoClient;

class DefaultUserSerializer implements SsoUserSerializerContract
{
    public function serialize(Authenticatable $user, SsoClient $client): array
    {
        return [
            'name' => $user->name ?? null,
            'email' => $user->email ?? null,
            // Clients must never link accounts by email unless this is true.
            // Fails closed: no verification data means false.
            'email_verified' => $user instanceof MustVerifyEmail
                ? $user->hasVerifiedEmail()
                : filled($user->email_verified_at ?? null),
        ];
    }
}
