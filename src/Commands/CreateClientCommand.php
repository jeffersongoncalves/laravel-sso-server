<?php

namespace JeffersonGoncalves\SsoServer\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use JeffersonGoncalves\SsoServer\Models\SsoClient;

class CreateClientCommand extends Command
{
    protected $signature = 'sso-server:client
        {name : Client application name}
        {redirect_uri : Exact callback URL on the client}
        {--slo= : Back-channel Single Logout webhook URL}';

    protected $description = 'Register an SSO client application and print its credentials';

    public function handle(): int
    {
        foreach (array_filter([$this->argument('redirect_uri'), $this->option('slo')]) as $url) {
            if (! filter_var($url, FILTER_VALIDATE_URL)) {
                $this->error("Invalid URL: {$url}");

                return self::FAILURE;
            }
        }

        $secret = Str::random(64);

        $client = SsoClient::create([
            'name' => $this->argument('name'),
            'client_id' => (string) Str::uuid(),
            'client_secret' => $secret,
            'redirect_uri' => $this->argument('redirect_uri'),
            'slo_webhook_url' => $this->option('slo'),
            'is_active' => true,
        ]);

        $this->info('SSO client created. Store the secret on the client app (SSO_CLIENT_SECRET).');
        $this->table(['Key', 'Value'], [
            ['client_id', $client->client_id],
            ['client_secret', $secret],
            ['redirect_uri', $client->redirect_uri],
            ['slo_webhook_url', $client->slo_webhook_url ?? '-'],
        ]);

        return self::SUCCESS;
    }
}
