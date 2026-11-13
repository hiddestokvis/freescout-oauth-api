<?php

namespace Modules\OAuthApi\Entities;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Modules\OAuthApi\Support\Scopes;
use Modules\OAuthApi\Support\Secrets;
use Modules\OAuthApi\Support\Settings;

/**
 * An access token and its refresh token.
 */
class Token extends Model
{
    protected $table = 'oauthapi_tokens';

    protected $casts = [
        'scopes' => 'array',
    ];

    protected $dates = [
        'access_expires_at',
        'refresh_expires_at',
        'rotated_at',
        'revoked_at',
    ];

    public function authorization()
    {
        return $this->belongsTo(Authorization::class, 'authorization_id');
    }

    /**
     * Create a token pair. Returns [Token, plain access token, plain
     * refresh token]; the plain values are never stored.
     */
    public static function issue(Authorization $authorization, array $scopes, $auth_code_id = null)
    {
        $access = Secrets::generate(Secrets::ACCESS_TOKEN_PREFIX);
        $refresh = Secrets::generate(Secrets::REFRESH_TOKEN_PREFIX);

        $token = new self();
        $token->authorization_id = $authorization->id;
        $token->auth_code_id = $auth_code_id;
        $token->access_hash = Secrets::hash($access);
        $token->refresh_hash = Secrets::hash($refresh);
        $token->scopes = Scopes::valid($scopes);
        $token->access_expires_at = Carbon::now()->addMinutes(Settings::accessTokenTtlMinutes());
        $token->refresh_expires_at = Carbon::now()->addDays(Settings::refreshTokenTtlDays());
        $token->save();

        return [$token, $access, $refresh];
    }

    public static function findByAccess($plain)
    {
        if (!Secrets::isAccessToken($plain)) {
            return null;
        }

        return self::where('access_hash', Secrets::hash($plain))->first();
    }

    public static function findByRefresh($plain)
    {
        if (!is_string($plain) || strpos($plain, Secrets::REFRESH_TOKEN_PREFIX) !== 0) {
            return null;
        }

        return self::where('refresh_hash', Secrets::hash($plain))->first();
    }

    public function isRevoked()
    {
        return !empty($this->revoked_at);
    }

    public function isAccessValid()
    {
        return !$this->isRevoked() && $this->access_expires_at && $this->access_expires_at->isFuture();
    }

    public function isRefreshExpired()
    {
        return !$this->refresh_expires_at || $this->refresh_expires_at->isPast();
    }

    /**
     * Mark the refresh token as exchanged. Returns false when it already
     * was: that is a replay.
     */
    public function markRotated()
    {
        $updated = self::where('id', $this->id)
            ->whereNull('rotated_at')
            ->update(['rotated_at' => Carbon::now()]);

        return $updated == 1;
    }

    public function revoke()
    {
        if (!$this->revoked_at) {
            $this->revoked_at = Carbon::now();
            $this->save();
        }
    }

    /**
     * Scopes this token may use right now: its own, cut down to what the
     * user still agrees to and the application is still allowed.
     */
    public function effectiveScopes()
    {
        $authorization = $this->authorization;
        if (!$authorization) {
            return [];
        }

        return array_values(array_intersect(Scopes::valid($this->scopes), $authorization->effectiveScopes()));
    }

    /**
     * Seconds until the access token expires.
     */
    public function expiresIn()
    {
        return max(0, $this->access_expires_at->getTimestamp() - time());
    }
}
