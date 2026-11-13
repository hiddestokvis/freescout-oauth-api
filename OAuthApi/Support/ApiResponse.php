<?php

namespace Modules\OAuthApi\Support;

/**
 * JSON responses for API requests refused by this module. The body has
 * the same shape as the API & Webhooks module's own errors, and CORS
 * headers are added the same way, so clients see one consistent API.
 */
class ApiResponse
{
    public static function json($data, $status = 200, $headers = [])
    {
        return self::withCors(response()->json($data, $status, $headers));
    }

    public static function error($message, $status, $detail = '', $path = '', $headers = [])
    {
        $errors = [];
        if ($detail !== '') {
            $errors[] = [
                'path'    => $path,
                'message' => $detail,
                'source'  => 'JSON',
            ];
        }

        return self::json([
            'message'   => $message,
            '_embedded' => ['errors' => $errors],
        ], $status, $headers);
    }

    public static function badRequest($detail, $path = '')
    {
        return self::error('Error occurred', 400, $detail, $path);
    }

    public static function notFound()
    {
        return self::error('Not Found', 404);
    }

    public static function forbidden($detail)
    {
        return self::error('Forbidden', 403, $detail);
    }

    /**
     * 401 for a missing, expired or revoked access token (RFC 6750).
     */
    public static function invalidToken($detail = 'The access token is invalid, expired or revoked.')
    {
        return self::error('Not Authorized', 401, $detail, '', [
            'WWW-Authenticate' => 'Bearer realm="FreeScout API", error="invalid_token"',
        ]);
    }

    /**
     * 403 for a token that lacks the scope an endpoint needs (RFC 6750).
     */
    public static function insufficientScope($scope)
    {
        return self::error('Forbidden', 403, 'This access token does not have the "'.$scope.'" scope.', '', [
            'WWW-Authenticate' => 'Bearer realm="FreeScout API", error="insufficient_scope", scope="'.$scope.'"',
        ]);
    }

    /**
     * The CORS headers the API & Webhooks module adds, from its own
     * "CORS hosts" setting.
     */
    public static function corsHeaders($methods = 'GET, POST, PUT, DELETE, OPTIONS')
    {
        $hosts = trim((string) config('apiwebhooks.cors_hosts'));
        if (!$hosts) {
            return [];
        }

        return [
            'Access-Control-Allow-Origin'  => $hosts,
            'Access-Control-Allow-Headers' => 'Content-Type,Authorization,X-FreeScout-API-Key',
            'Access-Control-Allow-Methods' => $methods,
        ];
    }

    public static function withCors($response, $methods = 'GET, POST, PUT, DELETE, OPTIONS')
    {
        foreach (self::corsHeaders($methods) as $name => $value) {
            $response->headers->set($name, $value);
        }

        return $response;
    }
}
