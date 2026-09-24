<?php

namespace JeffersonGoncalves\SsoServer\Commands;

use Illuminate\Console\Command;
use JeffersonGoncalves\SsoServer\Services\ServerTokenManager;

class GenerateKeysCommand extends Command
{
    protected $signature = 'sso-server:keys {--keep= : Key pairs to retain (defaults to sso-server.keys.keep)}';

    protected $description = 'Generate a new RS256 signing key pair (key rotation)';

    public function handle(ServerTokenManager $tokens): int
    {
        $keep = $this->option('keep');

        $kid = $tokens->generateKeyPair($keep !== null ? (int) $keep : null);

        $this->info("New signing key: {$kid}. Older keys stay in the JWKS until pruned.");

        return self::SUCCESS;
    }
}
