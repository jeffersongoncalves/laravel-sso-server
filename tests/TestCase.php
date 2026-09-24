<?php

namespace JeffersonGoncalves\SsoServer\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use JeffersonGoncalves\SsoServer\Models\SsoClient;
use JeffersonGoncalves\SsoServer\SsoServerServiceProvider;
use JeffersonGoncalves\SsoServer\Tests\Models\User;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    use RefreshDatabase;

    protected string $keysPath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->artisan('sso-server:keys')->assertSuccessful();
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->keysPath);

        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [
            SsoServerServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $this->keysPath = sys_get_temp_dir().'/sso-server-keys-'.Str::random(8);

        $app['config']->set('app.key', 'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('app.url', 'https://idp.test');
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('sso-server.keys.path', $this->keysPath);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');

        // Stubs are published into the host app; mirror that here, in order
        // (sessions reference clients).
        $tempPath = sys_get_temp_dir().'/laravel-sso-server-migrations';
        File::ensureDirectoryExists($tempPath);

        foreach (['create_sso_clients_table', 'create_sso_active_sessions_table'] as $index => $name) {
            copy(__DIR__."/../database/migrations/{$name}.php.stub", $tempPath.sprintf('/%03d_%s.php', $index, $name));
        }

        $this->loadMigrationsFrom($tempPath);
    }

    protected function makeClient(array $attributes = []): SsoClient
    {
        return SsoClient::create(array_merge([
            'name' => 'Client App',
            'client_id' => (string) Str::uuid(),
            'client_secret' => 'secret-'.Str::random(32),
            'redirect_uri' => 'https://client.test/sso/callback',
            'slo_webhook_url' => 'https://client.test/sso/logout',
            'is_active' => true,
        ], $attributes));
    }

    protected function makeUser(): User
    {
        return User::create(['name' => 'Jane', 'email' => Str::random(8).'@example.com', 'password' => 'x']);
    }
}
