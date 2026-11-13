<?php

namespace Modules\OAuthApi\Http\Middleware;

use Closure;
use Modules\OAuthApi\Support\Access;
use Modules\OAuthApi\Support\ApiResponse;
use Modules\OAuthApi\Support\EndpointGuard;
use Modules\OAuthApi\Support\ListFilter;
use Modules\OAuthApi\Support\ListScopes;
use Modules\OAuthApi\Support\Scopes;
use Modules\OAuthApi\Support\TokenAuth;
use Modules\OAuthApi\Support\WebhookManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Lets OAuth access tokens use the API & Webhooks module's API.
 *
 * Registered as global middleware, so it runs before the API & Webhooks
 * auth middleware (which is attached to its routes and only knows the one
 * master key). For a request carrying one of our access tokens it:
 *
 *  1. validates the token, its authorization, application and user;
 *  2. finds the route the request is for, and refuses endpoints it does
 *     not know (fail closed);
 *  3. checks the token's scope for that endpoint;
 *  4. checks the request against the user's own FreeScout permissions
 *     (EndpointGuard), or answers it itself for webhooks;
 *  5. only then swaps in the master API key, so the API & Webhooks module
 *     runs the request as usual;
 *  6. filters list responses to what the user can see (ListFilter).
 *
 * Requests without one of our tokens pass through untouched. Nothing is
 * swapped before every check has passed, and any error answers with a
 * failure, never with an unchecked request.
 */
class AuthenticateOAuthToken
{
    const API_CONTROLLER = 'Modules\ApiWebhooks\Http\Controllers\ApiController@';

    public function handle($request, Closure $next)
    {
        if (config('oauthapi.disabled')
            || $request->getMethod() == 'OPTIONS'
            || (!$request->is('api/*') && !$request->is('*/api/*'))
        ) {
            return $next($request);
        }

        $plain = TokenAuth::presentedToken($request);
        if ($plain === null) {
            // The master key, or no key at all: not ours.
            return $next($request);
        }

        try {
            $result = $this->authorizeRequest($request, $plain);
        } catch (\Throwable $e) {
            \Helper::logException($e, '[OAuthApi]');

            return ApiResponse::error('Server Error', 500);
        }

        if ($result instanceof Response) {
            return $result;
        }

        try {
            ListScopes::apply($result['method'], $result['user']);
        } catch (\Throwable $e) {
            ListScopes::remove();
            \Helper::logException($e, '[OAuthApi]');

            return ApiResponse::error('Server Error', 500);
        }

        try {
            $response = $next($request);
        } finally {
            ListScopes::remove();
        }

        // Recorded here, after FreeScout's TrustProxies middleware has run,
        // so it is the client's IP and not a proxy's.
        $result['authorization']->recordUsage($request->ip());

        try {
            return ListFilter::apply($result['method'], $response, $result['user']);
        } catch (\Throwable $e) {
            // Never hand out a list that could not be filtered.
            \Helper::logException($e, '[OAuthApi]');

            return ApiResponse::error('Server Error', 500);
        }
    }

    /**
     * Returns a response to send instead, or the request context when the
     * request may go ahead.
     */
    protected function authorizeRequest($request, $plain)
    {
        $token = TokenAuth::resolve($plain);
        if (!$token) {
            return ApiResponse::invalidToken();
        }

        $authorization = $token->authorization;
        $user = $authorization->user;

        if (!class_exists('\ApiWebhooks')) {
            return ApiResponse::error('The API & Webhooks module is not active.', 503);
        }

        if (!Access::apiAllowed($user)) {
            return ApiResponse::forbidden('API access is not enabled for this user.');
        }

        // Global middleware runs before routing, so find the route here.
        $route = $this->matchRoute($request);
        $webhook_id = null;

        if ($route instanceof Response) {
            // Webhook endpoints are answered by this module, so they work
            // even where the API & Webhooks version lacks the route.
            $endpoint = WebhookManager::endpointFromPath($request);
            if (!$endpoint) {
                return $route;
            }
            list($method, $webhook_id) = $endpoint;
        } else {
            if (strpos($route->getActionName(), self::API_CONTROLLER) !== 0) {
                return ApiResponse::forbidden('This endpoint is not available to OAuth access tokens.');
            }
            $method = $route->getActionMethod();
            $webhook_id = $route->parameter('webhookId');
        }

        $scope = Scopes::forEndpoint($method);

        if (!$scope && !Scopes::isUnscoped($method)) {
            \Log::error('[OAuthApi] API endpoint "'.$method.'" is not known to the OAuth API module; OAuth request refused. Update the module.');

            return ApiResponse::forbidden('This endpoint is not available to OAuth access tokens.');
        }

        if ($scope && !in_array($scope, $token->effectiveScopes(), true)) {
            return ApiResponse::insufficientScope($scope);
        }

        // Webhook endpoints are answered here: see WebhookManager.
        if (WebhookManager::handles($method)) {
            $authorization->recordUsage($request->ip());

            return WebhookManager::handle($method, $request, $webhook_id, $user, $authorization);
        }

        $denied = EndpointGuard::check($method, $request, $route, $user);
        if ($denied) {
            return $denied;
        }

        // Every check passed: let the API & Webhooks module serve it. Its
        // auth reads the api_key parameter first, then the header, so both
        // are set. The master key is read live, so regenerating it does
        // not affect OAuth tokens.
        $master = \ApiWebhooks::getApiKey();
        $request->headers->set('X-FreeScout-API-Key', $master);
        if ($request->input('api_key') !== null) {
            $request->merge(['api_key' => $master]);
            if ($request->query->has('api_key')) {
                $request->query->set('api_key', $master);
            }
        }

        $request->attributes->set('oauthapi_user', $user);
        $request->attributes->set('oauthapi_token', $token);
        $request->attributes->set('oauthapi_method', $method);

        $this->actAsUser($request, $user, $token, $authorization);

        return ['method' => $method, 'user' => $user, 'authorization' => $authorization];
    }

    /**
     * API & Webhooks 1.0.11x has personal API keys, and its controller then
     * applies the key owner's access itself (mailboxes, conversation
     * visibility, acting user, admin-only endpoints). Run OAuth requests
     * the same way, as a second layer on top of EndpointGuard: an
     * in-memory key for the token's user (never saved; nothing appears
     * under "My API Keys"), and the user logged in for this request only,
     * exactly as the API & Webhooks auth middleware does for its own keys.
     * On older versions there is nothing to do.
     */
    protected function actAsUser($request, $user, $token, $authorization)
    {
        $class = '\Modules\ApiWebhooks\Entities\ApiKey';
        if (!class_exists($class)) {
            return;
        }

        $write_scopes = [Scopes::CONVERSATIONS_WRITE, Scopes::CONVERSATIONS_DELETE, Scopes::CUSTOMERS_WRITE, Scopes::USERS_WRITE];

        $key = new $class();
        $key->user_id = $user->id;
        $key->name = 'OAuth: '.($authorization->client ? $authorization->client->name : '');
        $key->ability = array_intersect($write_scopes, $token->effectiveScopes()) ? $class::ABILITY_WRITE : $class::ABILITY_READ;
        $key->mailboxes = null;
        $key->setRelation('user', $user);

        $request->attributes->set('user_api_key', $key);
        \Auth::setUser($user);
    }

    protected function matchRoute($request)
    {
        try {
            return app('router')->getRoutes()->match($request);
        } catch (\Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException $e) {
            return ApiResponse::error('Method Not Allowed', 405);
        } catch (\Symfony\Component\HttpKernel\Exception\NotFoundHttpException $e) {
            return ApiResponse::notFound();
        }
    }
}
