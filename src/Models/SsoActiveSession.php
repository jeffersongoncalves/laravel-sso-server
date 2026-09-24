<?php

namespace JeffersonGoncalves\SsoServer\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $client_id
 * @property string $user_id
 * @property string $session_token_hash
 * @property Carbon $expires_at
 * @property-read SsoClient|null $client
 */
class SsoActiveSession extends Model
{
    protected $fillable = [
        'client_id',
        'user_id',
        'session_token_hash',
        'expires_at',
    ];

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
        ];
    }

    public function getTable(): string
    {
        return config('sso-server.tables.active_sessions', 'sso_active_sessions');
    }

    /** @return BelongsTo<SsoClient, $this> */
    public function client(): BelongsTo
    {
        return $this->belongsTo(SsoClient::class, 'client_id');
    }
}
