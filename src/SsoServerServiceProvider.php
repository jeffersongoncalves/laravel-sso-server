<?php

namespace JeffersonGoncalves\SsoServer;

use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Event;
use JeffersonGoncalves\SsoServer\Commands\CreateClientCommand;
use JeffersonGoncalves\SsoServer\Commands\GenerateKeysCommand;
use JeffersonGoncalves\SsoServer\Commands\PruneExpiredSessionsCommand;
use JeffersonGoncalves\SsoServer\Contracts\SsoUserSerializerContract;
use JeffersonGoncalves\SsoServer\Contracts\TokenRepositoryContract;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SsoServerServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-sso-server')
            ->hasConfigFile()
            ->hasMigrations([
                'create_sso_clients_table',
                'create_sso_active_sessions_table',
            ])
            ->hasRoute('web')
            ->hasCommands([
                CreateClientCommand::class,
                GenerateKeysCommand::class,
                PruneExpiredSessionsCommand::class,
            ]);
    }

    public function packageRegistered(): void
    {
        $this->app->bind(SsoUserSerializerContract::class, fn ($app) => $app->make(config('sso-server.serializer')));
        $this->app->singleton(ServerTokenManager::class);
        $this->app->alias(ServerTokenManager::class, TokenRepositoryContract::class);
    }

    public function packageBooted(): void
    {
        Event::listen(Logout::class, function (Logout $event) {
            if ($event->user !== null && $event->guard === config('sso-server.guard', 'web')) {
                $this->app->make(ServerTokenManager::class)->logoutUser((string) $event->user->getAuthIdentifier());
            }
        });
    }
}
