<?php

namespace JeffersonGoncalves\SsoServer\Commands;

use Illuminate\Console\Command;
use JeffersonGoncalves\SsoServer\Models\SsoActiveSession;

class PruneExpiredSessionsCommand extends Command
{
    protected $signature = 'sso-server:prune {--hours=24 : Keep sessions expired less than this many hours ago}';

    protected $description = 'Delete expired SSO active sessions';

    public function handle(): int
    {
        // Grace period: expired rows still drive Single Logout for client
        // sessions that outlive the access token.
        $deleted = SsoActiveSession::query()
            ->where('expires_at', '<', now()->subHours((int) $this->option('hours')))
            ->delete();

        $this->info("Pruned {$deleted} expired SSO session(s).");

        return self::SUCCESS;
    }
}
