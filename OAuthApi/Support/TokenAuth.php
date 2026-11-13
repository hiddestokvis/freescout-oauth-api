<?php

namespace Modules\OAuthApi\Support;

use Illuminate\Http\Request;
use Modules\OAuthApi\Entities\Token;

/**
 * Finding and validating the access token on a request.
 */
class TokenAuth
{
    /**
     * The access token presented with a request, if it is one of ours.
     *
     * The usual place is "Authorization: Bearer". The X-FreeScout-API-Key
     * header and the api_key parameter are accepted too, so integrations
     * that only know FreeScout's API key fields can use an OAuth token.
     */
    public static function presentedToken(Request $request)
    {
        $candidates = [
            $request->bearerToken(),
            $request->header('X-FreeScout-API-Key'),
            $request->input('api_key'),
        ];

        foreach ($candidates as $candidate) {
            if (Secrets::isAccessToken($candidate)) {
                return trim($candidate);
            }
        }

        return null;
    }

    /**
     * The valid token for a plain access token, or null. Valid means: not
     * expired or revoked, its authorization is not revoked, the
     * application is enabled and the user is active.
     */
    public static function resolve($plain)
    {
        $token = Token::findByAccess($plain);

        if (!$token || !$token->isAccessValid()) {
            return null;
        }

        $authorization = $token->authorization;
        if (!$authorization || !$authorization->isUsable()) {
            return null;
        }

        return $token;
    }
}
