<?php

namespace JeffersonGoncalves\SsoServer\Events;

use Illuminate\Foundation\Events\Dispatchable;

class UserLoggedOutEvent
{
    use Dispatchable;

    /**
     * @param  list<string>  $clientIds  public client_id of every client that had a session
     */
    public function __construct(public string $userId, public array $clientIds) {}
}
