<?php

namespace JeffersonGoncalves\SsoServer\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use JeffersonGoncalves\SsoServer\Models\SsoClient;

class ClientAuthorizedEvent
{
    use Dispatchable;

    public function __construct(public SsoClient $client, public Authenticatable $user) {}
}
