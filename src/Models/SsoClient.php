<?php

namespace JeffersonGoncalves\SsoServer\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * @property int $id
 * @property string $name
 * @property string $client_id
 * @property string $client_secret
 * @property string $redirect_uri
 * @property string|null $slo_webhook_url
 * @property bool $is_active
 */
class SsoClient extends Model
{
    protected $fillable = [
        'name',
        'client_id',
        'client_secret',
        'redirect_uri',
        'slo_webhook_url',
        'is_active',
    ];

    protected $hidden = ['client_secret'];

    protected function casts(): array
    {
        return [
            'client_secret' => 'encrypted',
            'is_active' => 'boolean',
        ];
    }

    public function getTable(): string
    {
        return config('sso-server.tables.clients', 'sso_clients');
    }

    /** @return HasMany<SsoActiveSession, $this> */
    public function activeSessions(): HasMany
    {
        return $this->hasMany(SsoActiveSession::class, 'client_id');
    }

    public static function findActive(string $clientId): ?self
    {
        return static::query()->where('client_id', $clientId)->where('is_active', true)->first();
    }

    public function secretMatches(string $secret): bool
    {
        return hash_equals($this->client_secret, $secret);
    }
}
