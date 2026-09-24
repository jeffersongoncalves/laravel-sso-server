<?php

namespace JeffersonGoncalves\SsoServer\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use JeffersonGoncalves\SsoServer\Contracts\SsoUserSerializerContract;
use JeffersonGoncalves\SsoServer\Models\SsoClient;

class DefaultUserSerializer implements SsoUserSerializerContract
{
    public function serialize(Authenticatable $user, SsoClient $client): array
    {
        return [
            'name' => $user->name ?? null,
            'email' => $user->email ?? null,
        ];
    }
}
