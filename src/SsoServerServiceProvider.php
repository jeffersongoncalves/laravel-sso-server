<?php

namespace JeffersonGoncalves\SsoServer;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SsoServerServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-sso-server')
            ->hasConfigFile()
            ->hasViews()
            ->hasMigrations();
    }
}
