<?php

namespace JeffersonGoncalves\SsoServer\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use JeffersonGoncalves\SsoServer\Models\SsoClient;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

/**
 * Back-channel logout: POSTs a signed "logout" event to the client's
 * slo_webhook_url. The client verifies X-SSO-Signature (HMAC-SHA256 of
 * "{timestamp}.{body}" with its client secret), rejects stale timestamps and
 * already-seen jti values, then destroys the user's local session.
 */
class DispatchSingleLogoutJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 5;

    /** @var list<int> */
    public array $backoff = [10, 30, 60, 300];

    // The client was deleted meanwhile: nobody left to notify.
    public bool $deleteWhenMissingModels = true;

    public function __construct(public SsoClient $client, public string $userId)
    {
        $this->onConnection(config('sso-server.slo.connection'));
        $this->onQueue(config('sso-server.slo.queue'));
    }

    public function handle(): void
    {
        if (! $this->client->is_active || blank($this->client->slo_webhook_url)) {
            return;
        }

        $body = (string) json_encode([
            'event' => 'logout',
            'sub' => $this->userId,
            'aud' => $this->client->client_id,
            'iat' => time(),
            'jti' => (string) Str::uuid(),
        ]);

        Http::timeout((int) config('sso-server.slo.timeout', 10))
            ->withHeaders(ServerTokenManager::signatureHeaders($body, $this->client->client_secret))
            ->withBody($body, 'application/json')
            ->post($this->client->slo_webhook_url)
            ->throw();
    }
}
