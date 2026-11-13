<?php

namespace Modules\OAuthApi\Support;

/**
 * Generating and hashing tokens, codes and client secrets.
 *
 * Only an HMAC (keyed with APP_KEY) of each secret is stored. Secrets are
 * 256 bits from random_bytes, so a fast hash is enough; it runs on every
 * API request.
 */
class Secrets
{
    const ACCESS_TOKEN_PREFIX = 'fsat_';
    const REFRESH_TOKEN_PREFIX = 'fsrt_';
    const CLIENT_ID_PREFIX = 'fsc_';
    const CLIENT_SECRET_PREFIX = 'fscs_';

    public static function generate($prefix = '', $bytes = 32)
    {
        return $prefix.bin2hex(random_bytes($bytes));
    }

    public static function hash($plain)
    {
        return hash_hmac('sha256', (string) $plain, (string) config('app.key'));
    }

    /**
     * Whether a string looks like one of our access tokens.
     */
    public static function isAccessToken($value)
    {
        return is_string($value) && strpos($value, self::ACCESS_TOKEN_PREFIX) === 0;
    }
}
