<?php

namespace JeffersonGoncalves\SsoServer\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use JeffersonGoncalves\SsoServer\Models\SsoClient;

interface SsoUserSerializerContract
{
    /**
     * Claims sent to the client, in the access token and from /userinfo
     * (e.g. name, email, roles, permissions, tenant_id). Reserved JWT claims
     * (iss, sub, aud, iat, nbf, exp, jti) are set by the server and win.
     *
     * @return array<string, mixed>
     */
    public function serialize(Authenticatable $user, SsoClient $client): array;
}
