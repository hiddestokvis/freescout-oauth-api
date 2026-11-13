<?php

namespace Modules\OAuthApi\Support;

/**
 * The module's stored settings, with sane bounds.
 */
class Settings
{
    const ACCESS_TOKEN_TTL = 'oauthapi.access_token_ttl';    // minutes
    const REFRESH_TOKEN_TTL = 'oauthapi.refresh_token_ttl';  // days

    const DEFAULT_ACCESS_TOKEN_TTL = 60;
    const DEFAULT_REFRESH_TOKEN_TTL = 30;

    // Authorization codes are exchanged right away; ten minutes is the
    // upper bound RFC 6749 recommends.
    const CODE_TTL_MINUTES = 10;

    public static function accessTokenTtlMinutes()
    {
        return self::bounded(\App\Option::get(self::ACCESS_TOKEN_TTL, self::DEFAULT_ACCESS_TOKEN_TTL), 5, 1440, self::DEFAULT_ACCESS_TOKEN_TTL);
    }

    public static function refreshTokenTtlDays()
    {
        return self::bounded(\App\Option::get(self::REFRESH_TOKEN_TTL, self::DEFAULT_REFRESH_TOKEN_TTL), 1, 365, self::DEFAULT_REFRESH_TOKEN_TTL);
    }

    protected static function bounded($value, $min, $max, $default)
    {
        if (!is_numeric($value)) {
            return $default;
        }

        return max($min, min($max, (int) $value));
    }

    /**
     * The issuer identifier: the FreeScout base URL.
     */
    public static function issuer()
    {
        return rtrim(config('app.url'), '/');
    }
}
