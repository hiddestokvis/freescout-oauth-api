<?php

namespace Modules\OAuthApi\Console;

use Carbon\Carbon;
use Illuminate\Console\Command;
use Modules\OAuthApi\Entities\AuthCode;
use Modules\OAuthApi\Entities\Token;

/**
 * Deletes authorization codes and tokens that can no longer be used.
 * Scheduled daily.
 */
class Purge extends Command
{
    protected $signature = 'oauthapi:purge';

    protected $description = 'Delete expired OAuth authorization codes and tokens';

    public function handle()
    {
        if (!\Schema::hasTable('oauthapi_tokens')) {
            return;
        }

        $day_ago = Carbon::now()->subDay();

        $codes = AuthCode::where('expires_at', '<', $day_ago)->delete();

        // Rotated refresh tokens are kept until they would have expired,
        // so a replay is still recognised as one until then.
        $tokens = Token::where('refresh_expires_at', '<', $day_ago)
            ->orWhere(function ($query) use ($day_ago) {
                $query->whereNotNull('revoked_at')
                    ->where('revoked_at', '<', $day_ago)
                    ->where('access_expires_at', '<', $day_ago);
            })
            ->delete();

        $this->info('Deleted '.$codes.' authorization codes and '.$tokens.' tokens.');
    }
}
