<?php

namespace Modules\OAuthApi\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Modules\OAuthApi\Entities\AuthCode;
use Modules\OAuthApi\Entities\Authorization;
use Modules\OAuthApi\Entities\Client;
use Modules\OAuthApi\Entities\Token;
use Modules\OAuthApi\Support\Access;
use Modules\OAuthApi\Support\ApiResponse;
use Modules\OAuthApi\Support\AuthorizeRequest;
use Modules\OAuthApi\Support\Scopes;
use Modules\OAuthApi\Support\Settings;
use Modules\OAuthApi\Support\TokenAuth;

/**
 * The OAuth 2.0 authorization server: authorization code grant with PKCE
 * and rotating refresh tokens (RFC 6749, 7636, 7009, 8414).
 */
class OAuthController extends Controller
{
    /**
     * GET /oauth/authorize — the consent screen. The user is logged in
     * (the "auth" middleware sends them to the login page first).
     */
    public function showAuthorize(Request $request)
    {
        if ($response = $this->unavailable()) {
            return $response;
        }

        $params = AuthorizeRequest::fromRequest($request);
        if ($params->page_error) {
            return $this->errorPage($params->page_error);
        }
        if ($params->redirect_error) {
            return $this->sendBack($params->errorRedirectUrl(), $params->client);
        }

        $user = auth()->user();
        if (!Access::apiAllowed($user)) {
            return $this->errorPage(__('Your account is not allowed to use the API. Ask an administrator to give you the "Users are allowed to access API" permission.'));
        }

        $authorization = Authorization::where('client_id', $params->client->id)->where('user_id', $user->id)->first();

        // Already authorized for these scopes: no need to ask again. Not for
        // public clients: their redirect can be a loopback port any local
        // program could listen on (RFC 8252 section 8.6), so the user
        // confirms every time.
        if ($authorization && $authorization->covers($params->scopes)
            && $params->prompt !== 'consent' && $params->client->confidential
        ) {
            return $this->issueCode($params, $authorization);
        }
        if ($params->prompt === 'none') {
            return $this->sendBack($params->errorRedirectUrl('consent_required', 'The user has not authorized this application yet.'), $params->client);
        }

        return $this->noFraming(response()->view('oauthapi::authorize', [
            'params'   => $params,
            'client'   => $params->client,
            'user'     => $user,
            'scopes'   => $params->scopes,
            'previous' => ($authorization && !$authorization->isRevoked()) ? Scopes::valid($authorization->scopes) : [],
        ]));
    }

    /**
     * POST /oauth/authorize — the user's answer on the consent screen.
     */
    public function decide(Request $request)
    {
        if ($response = $this->unavailable()) {
            return $response;
        }

        // Everything is validated again: the form fields are not trusted.
        $params = AuthorizeRequest::fromRequest($request);
        if ($params->page_error) {
            return $this->errorPage($params->page_error);
        }
        if ($params->redirect_error) {
            return $this->sendBack($params->errorRedirectUrl(), $params->client);
        }

        if ($request->input('decision') !== 'approve') {
            return $this->sendBack($params->errorRedirectUrl('access_denied', 'The user did not authorize the application.'), $params->client);
        }

        $user = auth()->user();
        if (!Access::apiAllowed($user)) {
            return $this->errorPage(__('Your account is not allowed to use the API. Ask an administrator to give you the "Users are allowed to access API" permission.'));
        }

        $authorization = Authorization::firstOrNew([
            'client_id' => $params->client->id,
            'user_id'   => $user->id,
        ]);

        // Scopes add up over consents; a revoked authorization starts over.
        $previous = ($authorization->exists && !$authorization->isRevoked()) ? Scopes::valid($authorization->scopes) : [];
        $authorization->scopes = Scopes::valid(array_merge($previous, $params->scopes));
        $authorization->revoked_at = null;
        $authorization->save();

        return $this->issueCode($params, $authorization);
    }

    /**
     * POST /oauth/token
     */
    public function token(Request $request)
    {
        if (config('oauthapi.disabled')) {
            return $this->oauthError('temporarily_unavailable', 'OAuth is switched off on this server.', 503);
        }

        $client = $this->authenticateClient($request);
        if (!$client instanceof Client) {
            return $client;
        }

        $grant_type = $request->input('grant_type');

        if ($grant_type === 'authorization_code') {
            return $this->exchangeCode($request, $client);
        }
        if ($grant_type === 'refresh_token') {
            return $this->refresh($request, $client);
        }

        return $this->oauthError('unsupported_grant_type', 'Supported grant types: authorization_code, refresh_token.');
    }

    /**
     * POST /oauth/revoke (RFC 7009). Answers 200 whether or not the token
     * existed.
     */
    public function revoke(Request $request)
    {
        $client = $this->authenticateClient($request);
        if (!$client instanceof Client) {
            return $client;
        }

        $plain = $request->input('token');
        $token = Token::findByAccess($plain) ?: Token::findByRefresh($plain);

        if ($token && $token->authorization && $token->authorization->client_id == $client->id) {
            $token->revoke();
        }

        return $this->tokenEndpointResponse([]);
    }

    /**
     * GET /oauth/userinfo — who the access token belongs to.
     */
    public function userinfo(Request $request)
    {
        $plain = TokenAuth::presentedToken($request);
        $token = (!config('oauthapi.disabled') && $plain) ? TokenAuth::resolve($plain) : null;

        if (!$token) {
            return ApiResponse::invalidToken();
        }

        $user = $token->authorization->user;
        if (!Access::apiAllowed($user)) {
            return ApiResponse::forbidden('API access is not enabled for this user.');
        }

        $data = class_exists('\ApiWebhooks') ? \ApiWebhooks::formatEntity($user) : null;
        if (!is_array($data)) {
            $data = [
                'id'        => $user->id,
                'firstName' => $user->first_name,
                'lastName'  => $user->last_name,
                'email'     => $user->email,
            ];
        }
        $data['role'] = $user->isAdmin() ? 'admin' : 'user';
        $data['scope'] = Scopes::toString($token->effectiveScopes());

        return ApiResponse::json($data, 200, ['Cache-Control' => 'no-store']);
    }

    /**
     * GET /.well-known/oauth-authorization-server (RFC 8414)
     */
    public function metadata()
    {
        return ApiResponse::json([
            'issuer'                                => Settings::issuer(),
            'authorization_endpoint'                => route('oauthapi.authorize'),
            'token_endpoint'                        => route('oauthapi.token'),
            'revocation_endpoint'                   => route('oauthapi.revoke'),
            'userinfo_endpoint'                     => route('oauthapi.userinfo'),
            'scopes_supported'                      => Scopes::all(),
            'response_types_supported'              => ['code'],
            'response_modes_supported'              => ['query'],
            'grant_types_supported'                 => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported'      => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'revocation_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'authorization_response_iss_parameter_supported' => true,
        ]);
    }

    /**
     * CORS preflight for the endpoints browser apps call directly.
     */
    public function preflight()
    {
        return ApiResponse::withCors(response('', 204), 'GET, POST, OPTIONS');
    }

    // Authorization code grant.

    protected function exchangeCode(Request $request, Client $client)
    {
        $code = AuthCode::findByPlain($request->input('code'));
        $authorization = $code ? $code->authorization : null;

        if (!$code || !$authorization || $authorization->client_id != $client->id) {
            return $this->oauthError('invalid_grant', 'The authorization code is invalid.');
        }

        if ($code->used_at) {
            return $this->codeReplayed($code);
        }

        if ($code->isExpired()) {
            return $this->oauthError('invalid_grant', 'The authorization code has expired.');
        }

        if ($code->redirect_uri !== null && $request->input('redirect_uri') !== $code->redirect_uri) {
            return $this->oauthError('invalid_grant', 'redirect_uri does not match the authorization request.');
        }

        if (!$code->verifierMatches($request->input('code_verifier'))) {
            return $this->oauthError('invalid_grant', 'code_verifier does not match the code challenge.');
        }

        if (!$authorization->isUsable() || !Access::apiAllowed($authorization->user)) {
            return $this->oauthError('invalid_grant', 'The authorization is no longer valid.');
        }

        // Atomic: of two simultaneous exchanges only one gets here.
        if (!$code->markUsed()) {
            return $this->codeReplayed($code);
        }

        $scopes = array_values(array_intersect(Scopes::valid($code->scopes), $authorization->effectiveScopes()));

        return $this->issueTokens($authorization, $scopes, $code->id);
    }

    /**
     * A code used twice may have been stolen: revoke what the first use
     * produced (RFC 6749 section 4.1.2).
     */
    protected function codeReplayed(AuthCode $code)
    {
        Token::where('auth_code_id', $code->id)->whereNull('revoked_at')->update(['revoked_at' => now()]);

        return $this->oauthError('invalid_grant', 'The authorization code has already been used.');
    }

    // Refresh token grant, with rotation.

    protected function refresh(Request $request, Client $client)
    {
        $token = Token::findByRefresh($request->input('refresh_token'));
        $authorization = $token ? $token->authorization : null;

        if (!$token || !$authorization || $authorization->client_id != $client->id) {
            return $this->oauthError('invalid_grant', 'The refresh token is invalid.');
        }

        if ($token->isRevoked() || $token->isRefreshExpired()) {
            return $this->oauthError('invalid_grant', 'The refresh token has expired or was revoked.');
        }

        if (!$authorization->isUsable() || !Access::apiAllowed($authorization->user)) {
            return $this->oauthError('invalid_grant', 'The authorization is no longer valid.');
        }

        $scopes = array_values(array_intersect(Scopes::valid($token->scopes), $authorization->effectiveScopes()));

        // A narrower scope may be asked for, never a wider one.
        if ($request->has('scope')) {
            $requested = Scopes::parse($request->input('scope'));
            if ($requested === null || array_diff($requested, $scopes)) {
                return $this->oauthError('invalid_scope', 'The requested scope is wider than the original grant.');
            }
            if ($requested) {
                $scopes = $requested;
            }
        }
        if (!$scopes) {
            return $this->oauthError('invalid_scope', 'No scope left to grant.');
        }

        // Atomic: a refresh token is exchanged once.
        if ($token->rotated_at || !$token->markRotated()) {
            // An old refresh token came back: someone else has a copy.
            // Revoke every token of the authorization; the user has to
            // authorize the application again.
            Token::where('authorization_id', $authorization->id)->whereNull('revoked_at')->update(['revoked_at' => now()]);
            \Log::error('[OAuthApi] Reused refresh token for authorization '.$authorization->id.' (application "'.$client->name.'"); all its tokens were revoked.');

            return $this->oauthError('invalid_grant', 'The refresh token has already been used.');
        }

        return $this->issueTokens($authorization, $scopes, $token->auth_code_id);
    }

    protected function issueTokens(Authorization $authorization, array $scopes, $auth_code_id)
    {
        if (!$scopes) {
            return $this->oauthError('invalid_scope', 'No scope left to grant.');
        }

        list($token, $access, $refresh) = Token::issue($authorization, $scopes, $auth_code_id);

        return $this->tokenEndpointResponse([
            'access_token'  => $access,
            'token_type'    => 'Bearer',
            'expires_in'    => $token->expiresIn(),
            'refresh_token' => $refresh,
            'scope'         => Scopes::toString($scopes),
        ]);
    }

    /**
     * Client authentication: HTTP Basic, or client_id / client_secret in
     * the body. Public clients send only client_id.
     */
    protected function authenticateClient(Request $request)
    {
        $client_id = null;
        $secret = null;
        $used_basic = false;

        $header = (string) $request->header('Authorization');
        if (stripos($header, 'Basic ') === 0) {
            $decoded = base64_decode(substr($header, 6), true);
            if ($decoded === false || strpos($decoded, ':') === false) {
                return $this->oauthError('invalid_client', 'Malformed Basic authorization header.', 401, true);
            }
            list($client_id, $secret) = explode(':', $decoded, 2);
            // RFC 6749 section 2.3.1: both parts are form-urlencoded.
            $client_id = urldecode($client_id);
            $secret = urldecode($secret);
            $used_basic = true;

            if ($request->has('client_id') && $request->input('client_id') !== $client_id) {
                return $this->oauthError('invalid_request', 'client_id does not match the Authorization header.');
            }
        } else {
            $client_id = $request->input('client_id');
            $secret = $request->input('client_secret');
        }

        $client = Client::findByClientId($client_id);

        if (!$client || !$client->active) {
            return $this->oauthError('invalid_client', 'Unknown or disabled client.', 401, $used_basic);
        }
        if ($client->confidential && !$client->checkSecret($secret)) {
            return $this->oauthError('invalid_client', 'Client authentication failed.', 401, $used_basic);
        }

        return $client;
    }

    // Responses.

    protected function issueCode(AuthorizeRequest $params, Authorization $authorization)
    {
        $code = AuthCode::issue(
            $authorization,
            $params->scopes,
            $params->redirect_uri_given ? $params->redirect_uri : null,
            $params->code_challenge,
            $params->code_challenge_method
        );

        return $this->sendBack($params->redirectUrl(['code' => $code]), $params->client);
    }

    /**
     * Send the browser back to the application.
     *
     * This is a page that forwards at once, not an HTTP redirect: the
     * FreeScout Content Security Policy only allows forms to submit to
     * FreeScout itself (form-action 'self'), and browsers apply that to
     * redirects after a form post too, such as the consent form or the
     * login form.
     */
    protected function sendBack($url, Client $client)
    {
        return $this->noFraming(response()->view('oauthapi::redirect', [
            'url'    => $url,
            'client' => $client,
        ])->header('Cache-Control', 'no-store')->header('Referrer-Policy', 'no-referrer'));
    }

    protected function errorPage($message)
    {
        return $this->noFraming(response()->view('oauthapi::error', ['message' => $message], 400));
    }

    protected function noFraming($response)
    {
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Content-Security-Policy', "frame-ancestors 'none'");

        return $response;
    }

    protected function unavailable()
    {
        if (config('oauthapi.disabled')) {
            return $this->errorPage(__('Connecting applications is switched off on this server.'));
        }

        return null;
    }

    protected function oauthError($error, $description, $status = 400, $basic_challenge = false)
    {
        $response = $this->tokenEndpointResponse([
            'error'             => $error,
            'error_description' => $description,
        ], $status);

        if ($status == 401 && $basic_challenge) {
            $response->headers->set('WWW-Authenticate', 'Basic realm="FreeScout OAuth"');
        }

        return $response;
    }

    protected function tokenEndpointResponse($data, $status = 200)
    {
        return ApiResponse::withCors(response()->json((object) $data, $status, [
            'Cache-Control' => 'no-store',
            'Pragma'        => 'no-cache',
        ]), 'GET, POST, OPTIONS');
    }
}
