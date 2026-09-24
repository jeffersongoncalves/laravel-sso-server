<?php

namespace JeffersonGoncalves\SsoServer\Tests;

use JeffersonGoncalves\SsoServer\SsoServerServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            SsoServerServiceProvider::class,
        ];
    }
}
